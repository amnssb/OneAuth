package database

import (
	"database/sql"
	"log"
	"runtime"
	"sync"

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
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE IF NOT EXISTS admin_users (
			username TEXT PRIMARY KEY,
			password_hash TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);`,
		`INSERT OR IGNORE INTO system_settings (setting_key, setting_value) VALUES
			('site_name', '统一身份认证中心'),
			('site_logo', ''),
			('background_url', 'https://images.unsplash.com/photo-1618005182384-a83a8bd57fbe?auto=format&fit=crop&w=1920&q=80'),
			('custom_css', ''),
			('target_group_id', '87654321'),
			('onebot_token', 'oneauth_secure_secret_token'),
			('code_ttl', '180');`,
	}

	for _, q := range queries {
		if _, err := WriteDB.Exec(q); err != nil {
			return err
		}
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
