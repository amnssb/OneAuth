package database

import (
	"database/sql"
	"fmt"
	"log"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// DB 是读连接池：WAL 模式下读与读、读与写互不阻塞，可多连接并行。
// WriteDB 是写连接池（单连接）：SQLite 同一时刻只允许一个写者，
// 在池层面串行化写入，从根上规避 SQLITE_BUSY 竞争与 busy_timeout 空转。
var (
	DB      *sql.DB
	WriteDB *sql.DB
)

// PRAGMA 通过 DSN 下发：连接池里的每一条新连接都会自动带上，
// 而不是只在某一条连接上执行一次（连接是无状态的，单独 Exec PRAGMA 不生效）。
const dsnPragmas = "?_pragma=journal_mode(WAL)" +
	"&_pragma=busy_timeout(5000)" +
	"&_pragma=synchronous(NORMAL)" +
	"&_pragma=foreign_keys(ON)" +
	"&_pragma=cache_size(-8000)" +
	"&_pragma=mmap_size(268435456)"

func InitDB(dbPath string) (*sql.DB, error) {
	writer, err := sql.Open("sqlite", dbPath+dsnPragmas)
	if err != nil {
		return nil, err
	}
	writer.SetMaxOpenConns(1)
	writer.SetMaxIdleConns(1)
	writer.SetConnMaxIdleTime(0)
	WriteDB = writer

	reader, err := sql.Open("sqlite", dbPath+dsnPragmas)
	if err != nil {
		writer.Close()
		return nil, err
	}
	readConns := runtime.NumCPU()
	if readConns < 2 {
		readConns = 2
	} else if readConns > 16 {
		readConns = 16
	}
	reader.SetMaxOpenConns(readConns)
	reader.SetMaxIdleConns(readConns)
	reader.SetConnMaxIdleTime(0)
	DB = reader

	if err := migrate(); err != nil {
		reader.Close()
		writer.Close()
		return nil, err
	}

	initSettingsCache()

	log.Printf("Database initialized successfully (WAL, read pool: %d conns, write pool: 1 conn)", readConns)
	return reader, nil
}

func migrate() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS system_settings (
			setting_key TEXT PRIMARY KEY,
			setting_value TEXT NOT NULL,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE IF NOT EXISTS oidc_clients (
			client_id TEXT PRIMARY KEY,
			client_secret_hash TEXT NOT NULL,
			client_name TEXT NOT NULL,
			redirect_uris TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			display_name TEXT,
			background_url TEXT,
			prompt_text TEXT,
			custom_css TEXT,
			target_group_id TEXT
		);`,
		`CREATE TABLE IF NOT EXISTS admin_users (
			username TEXT PRIMARY KEY,
			password_hash TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);`,
		// tenant_keys：每个 issuer_slug 独立的 RSA 签名密钥历史。retired_at
		// 为空表示当前在用签发密钥；轮换时旧行写入 retired_at 而不删除，
		// JWKS 端点靠这个字段决定宽限期内要不要继续公布旧公钥。
		`CREATE TABLE IF NOT EXISTS tenant_keys (
			slug TEXT NOT NULL,
			kid TEXT NOT NULL,
			private_pem TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			retired_at DATETIME,
			PRIMARY KEY (slug, kid)
		);`,
		`CREATE TABLE IF NOT EXISTS transient_sessions_backup (
			session_id TEXT PRIMARY KEY,
			client_id TEXT NOT NULL,
			redirect_uri TEXT NOT NULL,
			state TEXT,
			code_challenge TEXT,
			verify_code TEXT,
			group_id TEXT,
			provider TEXT,
			user_id TEXT,
			auth_code TEXT,
			status TEXT NOT NULL,
			expires_at DATETIME NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS transient_admin_sessions (
			token TEXT PRIMARY KEY,
			username TEXT NOT NULL,
			issued_at INTEGER NOT NULL,
			exp INTEGER NOT NULL
		);`,
		`INSERT OR IGNORE INTO system_settings (setting_key, setting_value) VALUES
			('site_name', '统一身份认证中心'),
			('site_logo', ''),
			('background_url', 'https://images.unsplash.com/photo-1618005182384-a83a8bd57fbe?auto=format&fit=crop&w=1920&q=80'),
			('custom_css', ''),
			('target_group_id', '87654321'),
			('onebot_token', 'oneauth_secure_secret_token'),
			('code_ttl', '180'),
			('demo_enabled', 'true'),
			('update_check_url', 'https://api.github.com/repos/amnssb/OneAuth/releases/latest'),
			('bot_status_cmd_enabled', 'true');`,
	}

	for _, q := range queries {
		if _, err := WriteDB.Exec(q); err != nil {
			return err
		}
	}

	// v2 迁移：per-client 登录页品牌覆盖；应用级验证群号 target_group_id
	// 也走同一列补齐。旧库的 oidc_clients 没有这几列，CREATE TABLE IF NOT
	// EXISTS 对已存在的表不生效，这里逐列幂等补齐。NULL / 空串 = 继承全局设置。
	existing := map[string]bool{}
	colRows, err := WriteDB.Query("PRAGMA table_info(oidc_clients)")
	if err != nil {
		return err
	}
	for colRows.Next() {
		var cid int
		var name, ctype string
		var notNull, pk int
		var dflt interface{}
		if err := colRows.Scan(&cid, &name, &ctype, &notNull, &dflt, &pk); err == nil {
			existing[name] = true
		}
	}
	colRows.Close()

	for _, col := range []string{"display_name", "background_url", "prompt_text", "custom_css", "target_group_id"} {
		if !existing[col] {
			if _, err := WriteDB.Exec("ALTER TABLE oidc_clients ADD COLUMN " + col + " TEXT"); err != nil {
				return err
			}
		}
	}

	// v3 迁移：多 Issuer 强制迁移。issuer_slug 是每个应用独立 Issuer 的路径
	// 标识（https://host/{slug}）；旧库没有这一列时先补列，再对所有
	// issuer_slug 为空的存量应用自动回填一个合法 slug —— 这是破坏性变更，
	// 存量接入方的 Issuer/发现地址会随之改变，回填结果会打印到启动日志。
	if !existing["issuer_slug"] {
		if _, err := WriteDB.Exec("ALTER TABLE oidc_clients ADD COLUMN issuer_slug TEXT"); err != nil {
			return err
		}
	}
	if err := backfillIssuerSlugs(); err != nil {
		return err
	}
	if _, err := WriteDB.Exec(
		"CREATE UNIQUE INDEX IF NOT EXISTS idx_oidc_clients_issuer_slug ON oidc_clients(issuer_slug)",
	); err != nil {
		return err
	}

	return nil
}

// slugPattern 与管理后台创建/编辑应用时使用的校验规则保持一致：
// 小写字母数字与短横线，2~32 个字符，首字符不能是短横线。
var slugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,31}$`)

// reservedSlugs 是与现有路由字面量冲突或语义混淆的保留字，创建/回填
// 时一律拒绝，防止 /{slug}/authorize 之类的通配路由抢占既有端点。
var reservedSlugs = map[string]bool{
	"login": true, "admin": true, "demo": true, "static": true,
	"api": true, "ws": true, "authorize": true, "token": true,
	"userinfo": true, "well-known": true, "callback": true,
	"health": true, "assets": true, "oneauth": true,
}

// ValidateSlug 校验管理后台传入的 issuer_slug 是否合法：格式符合
// slugPattern 且不是保留字。供 admin 包创建应用时调用，与回填逻辑共用
// 同一套规则，保证两条路径生成的 slug 语义一致。
func ValidateSlug(slug string) error {
	if !slugPattern.MatchString(slug) {
		return fmt.Errorf("issuer_slug 只能包含小写字母、数字、短横线，长度 2~32 且不以短横线开头")
	}
	if reservedSlugs[slug] {
		return fmt.Errorf("issuer_slug %q 是保留字，请换一个", slug)
	}
	return nil
}

// sanitizeSlugSeed 把任意字符串（通常是 client_id）规整成候选 slug：
// 转小写、非法字符替换为短横线、收敛连续短横线、裁剪长度。
func sanitizeSlugSeed(seed string) string {
	lower := strings.ToLower(seed)
	var b strings.Builder
	for _, r := range lower {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	out := regexp.MustCompile(`-+`).ReplaceAllString(b.String(), "-")
	out = strings.Trim(out, "-")
	if len(out) > 28 {
		out = out[:28]
	}
	return out
}

// backfillIssuerSlugs 为 issuer_slug 为空的存量应用自动生成唯一 slug。
// 候选来源是 client_id 规整后的结果；若为空、命中保留字或与已有 slug
// 冲突，则追加 "-app" 后缀，仍冲突则再追加序号，保证幂等（重复调用
// 不会改变已分配的 slug，只处理仍为空的行）。
func backfillIssuerSlugs() error {
	rows, err := WriteDB.Query("SELECT client_id, issuer_slug FROM oidc_clients")
	if err != nil {
		return err
	}
	type row struct{ clientID, slug string }
	var pending []row
	used := map[string]bool{}
	for rows.Next() {
		var id string
		var slug sql.NullString
		if err := rows.Scan(&id, &slug); err != nil {
			rows.Close()
			return err
		}
		if slug.Valid && slug.String != "" {
			used[slug.String] = true
			continue
		}
		pending = append(pending, row{clientID: id})
	}
	rows.Close()

	for _, p := range pending {
		seed := sanitizeSlugSeed(p.clientID)
		if seed == "" {
			seed = "app"
		}
		candidate := seed
		if reservedSlugs[candidate] {
			candidate = seed + "-app"
		}
		for i := 2; used[candidate] || reservedSlugs[candidate] || !slugPattern.MatchString(candidate); i++ {
			candidate = fmt.Sprintf("%s-%d", seed, i)
			if i > 1000 {
				return fmt.Errorf("为客户端 %s 分配 issuer_slug 失败：候选空间耗尽", p.clientID)
			}
		}
		if _, err := WriteDB.Exec(
			"UPDATE oidc_clients SET issuer_slug = ? WHERE client_id = ?", candidate, p.clientID,
		); err != nil {
			return err
		}
		used[candidate] = true
		log.Printf("[DB] 迁移：应用 %s 自动分配 issuer_slug=%s（Issuer 变为 https://<host>/%s）", p.clientID, candidate, candidate)
	}
	return nil
}

// ---- system_settings 进程内缓存 ----
// 设置项是典型的读多写少（每个登录页渲染、每条 OneBot 事件都会读），
// 缓存后这些热路径对 SQLite 的读取归零；SetSetting 写库成功后同步刷新缓存。
var (
	settingsMu    sync.RWMutex
	settingsCache map[string]string
)

func initSettingsCache() {
	m := make(map[string]string)
	rows, err := DB.Query("SELECT setting_key, setting_value FROM system_settings")
	if err == nil {
		for rows.Next() {
			var k, v string
			if err := rows.Scan(&k, &v); err == nil {
				m[k] = v
			}
		}
		rows.Close()
	} else {
		log.Printf("[DB] 设置缓存预热失败（将退回默认值）: %v", err)
	}

	settingsMu.Lock()
	settingsCache = m
	settingsMu.Unlock()
}

func GetSetting(key, defaultVal string) string {
	settingsMu.RLock()
	val, ok := settingsCache[key]
	settingsMu.RUnlock()
	if ok {
		return val
	}
	return defaultVal
}

func SetSetting(key, val string) error {
	_, err := WriteDB.Exec(`
		INSERT INTO system_settings (setting_key, setting_value, updated_at)
		VALUES (?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(setting_key) DO UPDATE SET
		setting_value = excluded.setting_value,
		updated_at = CURRENT_TIMESTAMP
	`, key, val)
	if err != nil {
		return err
	}

	settingsMu.Lock()
	if settingsCache != nil {
		settingsCache[key] = val
	}
	settingsMu.Unlock()
	return nil
}

// ---- 多 Issuer / issuer_slug ----

// ClientIDForSlug 按 issuer_slug 反查 client_id，供 /{slug}/... 路由解析
// 租户上下文使用；未命中返回 ok=false（含 slug 从未注册、或对应应用已被
// 删除的情况）。
func ClientIDForSlug(slug string) (string, bool) {
	var id string
	err := DB.QueryRow("SELECT client_id FROM oidc_clients WHERE issuer_slug = ?", slug).Scan(&id)
	return id, err == nil
}

// SlugForClient 返回某个 client_id 当前绑定的 issuer_slug；v3 迁移强制
// 给所有应用回填了 slug，正常情况下总能命中。
func SlugForClient(clientID string) (string, bool) {
	var slug sql.NullString
	err := DB.QueryRow("SELECT issuer_slug FROM oidc_clients WHERE client_id = ?", clientID).Scan(&slug)
	if err != nil || !slug.Valid || slug.String == "" {
		return "", false
	}
	return slug.String, true
}

// SlugTaken 供管理后台创建应用时校验 slug 唯一性（不区分是否已删除，
// 因为 issuer_slug 上有唯一索引，删除应用后旧 slug 立即可复用）。
func SlugTaken(slug string) (bool, error) {
	var count int
	err := DB.QueryRow("SELECT COUNT(*) FROM oidc_clients WHERE issuer_slug = ?", slug).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// SetClientIssuerSlug 在创建应用时一次性写入 issuer_slug；slug 创建后
// 在管理后台被视为不可变（改 slug 会让下游 Issuer 失效），这里不提供
// 独立的“更新 slug”入口。
func SetClientIssuerSlug(clientID, slug string) error {
	_, err := WriteDB.Exec("UPDATE oidc_clients SET issuer_slug = ? WHERE client_id = ?", slug, clientID)
	return err
}

// ---- tenant_keys：按 issuer_slug 隔离的签名密钥管理 ----

// TenantKeyRow 是 tenant_keys 一行的只读快照，PrivatePEM 为 PKCS1 PEM 编码。
type TenantKeyRow struct {
	Kid        string
	PrivatePEM string
	CreatedAt  string
}

// ActiveTenantKey 返回某租户当前在用（retired_at 为空）的签名密钥；
// 理论上每个 slug 至多一条在用记录，异常情况下取最新创建的一条兜底。
func ActiveTenantKey(slug string) (TenantKeyRow, bool) {
	var row TenantKeyRow
	err := DB.QueryRow(
		"SELECT kid, private_pem, created_at FROM tenant_keys WHERE slug = ? AND retired_at IS NULL ORDER BY created_at DESC LIMIT 1",
		slug,
	).Scan(&row.Kid, &row.PrivatePEM, &row.CreatedAt)
	return row, err == nil
}

// InsertTenantKey 落盘一把新生成的租户密钥（默认在用状态，retired_at 为空）。
func InsertTenantKey(slug, kid, privatePEM string) error {
	_, err := WriteDB.Exec(
		"INSERT INTO tenant_keys (slug, kid, private_pem) VALUES (?, ?, ?)", slug, kid, privatePEM,
	)
	return err
}

// RetireActiveTenantKeys 把某租户所有在用密钥标记为已退休（轮换时调用，
// 紧接着应插入一把新的在用密钥）。
func RetireActiveTenantKeys(slug string) error {
	_, err := WriteDB.Exec(
		"UPDATE tenant_keys SET retired_at = CURRENT_TIMESTAMP WHERE slug = ? AND retired_at IS NULL", slug,
	)
	return err
}

// TenantJWKSKeys 返回某租户在 JWKS 中应公布的全部公钥来源行：当前在用
// 密钥 + 宽限期内（未超过 grace）退休的旧密钥，新到旧排序，让刚轮换后
// 用旧密钥签发但还未过期的令牌仍可通过下游的验签。
func TenantJWKSKeys(slug string, grace time.Duration) ([]TenantKeyRow, error) {
	cutoff := time.Now().Add(-grace).UTC().Format("2006-01-02 15:04:05")
	rows, err := DB.Query(
		`SELECT kid, private_pem, created_at FROM tenant_keys
		 WHERE slug = ? AND (retired_at IS NULL OR retired_at >= ?)
		 ORDER BY created_at DESC`,
		slug, cutoff,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []TenantKeyRow
	for rows.Next() {
		var r TenantKeyRow
		if err := rows.Scan(&r.Kid, &r.PrivatePEM, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// PurgeExpiredTenantKeys 物理删除某租户宽限期已过的退休密钥；在用密钥
// （retired_at 为空）永不命中，不会被误删。
func PurgeExpiredTenantKeys(slug string, grace time.Duration) error {
	cutoff := time.Now().Add(-grace).UTC().Format("2006-01-02 15:04:05")
	_, err := WriteDB.Exec(
		"DELETE FROM tenant_keys WHERE slug = ? AND retired_at IS NOT NULL AND retired_at < ?",
		slug, cutoff,
	)
	return err
}

// GetClientBranding 返回一个 OIDC 客户端的登录页品牌覆盖与应用级验证群号
// （target_group_id）；未设置的字段为空串，由调用方回落到全局设置。这让
// 同一个 OneAuth 可以给多个接入项目呈现各自不同的登录页与核验群。
func GetClientBranding(clientID string) map[string]string {
	out := map[string]string{"display_name": "", "background_url": "", "prompt_text": "", "custom_css": "", "target_group_id": ""}
	if clientID == "" {
		return out
	}
	row := DB.QueryRow(`
		SELECT COALESCE(display_name, ''), COALESCE(background_url, ''),
		       COALESCE(prompt_text, ''), COALESCE(custom_css, ''),
		       COALESCE(target_group_id, '')
		FROM oidc_clients WHERE client_id = ?`, clientID)
	var dn, bg, pt, css, gid string
	if err := row.Scan(&dn, &bg, &pt, &css, &gid); err == nil {
		out["display_name"], out["background_url"] = dn, bg
		out["prompt_text"], out["custom_css"] = pt, css
		out["target_group_id"] = gid
	}
	return out
}
