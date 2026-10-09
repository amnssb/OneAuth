package database

import (
	"database/sql"
	"path/filepath"
	"testing"
)

// 反向 WS 口令必须始终是高熵随机值：空值与随源码公开的历史默认值都要被
// 轮换掉，否则 /ws/onebot 的“认证”形同虚设。
func TestOnebotTokenRotatesWhenMissingOrLegacy(t *testing.T) {
	initTestDB(t)

	tok := GetSetting("onebot_token", "")
	if tok == "" {
		t.Fatal("onebot_token must never be empty after InitDB")
	}
	if legacyOnebotTokens[tok] {
		t.Fatalf("legacy default token %q must be rotated", tok)
	}
	if len(tok) < 32 {
		t.Fatalf("generated token too short: %d chars", len(tok))
	}

	// 已有随机 Token 时不得再次轮换（否则每次重启都要改机器人配置）
	ensureOnebotToken()
	if again := GetSetting("onebot_token", ""); again != tok {
		t.Fatalf("stable token must not be rotated: %q -> %q", tok, again)
	}
}

// 历史公开默认值等同于没有口令，启动即换成随机值。
func TestOnebotTokenRotatesLegacyDefault(t *testing.T) {
	initTestDB(t)
	if err := SetSetting("onebot_token", "oneauth_secure_secret_token"); err != nil {
		t.Fatalf("set legacy token: %v", err)
	}
	ensureOnebotToken()
	got := GetSetting("onebot_token", "")
	if got == "oneauth_secure_secret_token" || got == "" {
		t.Fatalf("legacy default must be rotated, got %q", got)
	}
}

// 登出跳转白名单按应用注册，未注册的应用返回 nil（调用方退回同源/相对路径）。
func TestClientPostLogoutURIs(t *testing.T) {
	initTestDB(t)

	if _, err := WriteDB.Exec(
		`INSERT INTO oidc_clients (client_id, client_secret_hash, client_name, redirect_uris, issuer_slug, post_logout_redirect_uris)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		"pl_client", "h", "pl", "http://cb.local/cb", "pl-tenant",
		"http://app.local/goodbye, https://app.local/done",
	); err != nil {
		t.Fatalf("insert client: %v", err)
	}
	got := ClientPostLogoutURIs("pl_client")
	if len(got) != 2 || got[0] != "http://app.local/goodbye" || got[1] != "https://app.local/done" {
		t.Fatalf("unexpected whitelist: %#v", got)
	}

	if _, err := WriteDB.Exec(
		`INSERT INTO oidc_clients (client_id, client_secret_hash, client_name, redirect_uris, issuer_slug)
		 VALUES (?, ?, ?, ?, ?)`,
		"pl_empty", "h", "pl2", "http://cb.local/cb", "pl-tenant-2",
	); err != nil {
		t.Fatalf("insert client: %v", err)
	}
	if got := ClientPostLogoutURIs("pl_empty"); len(got) != 0 {
		t.Fatalf("client without whitelist must return empty, got %#v", got)
	}
	if got := ClientPostLogoutURIs("nope"); got != nil {
		t.Fatalf("unknown client must return nil, got %#v", got)
	}
	if got := ClientPostLogoutURIs(""); got != nil {
		t.Fatalf("empty client id must return nil, got %#v", got)
	}
}

// 旧库没有 post_logout_redirect_uris 列：migrate 必须幂等补列，
// 否则白名单一写就 SQL 报错。
func TestMigrateAddsPostLogoutColumn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open legacy db: %v", err)
	}
	// 手工搭一张 v1 形态的 oidc_clients（缺新列）
	if _, err := raw.Exec(`CREATE TABLE oidc_clients (
		client_id TEXT PRIMARY KEY,
		client_secret_hash TEXT NOT NULL,
		client_name TEXT NOT NULL,
		redirect_uris TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		t.Fatalf("create legacy table: %v", err)
	}
	if _, err := raw.Exec(`INSERT INTO oidc_clients (client_id, client_secret_hash, client_name, redirect_uris)
		VALUES ('legacy', 'h', 'legacy app', 'http://cb.local/cb')`); err != nil {
		t.Fatalf("seed legacy row: %v", err)
	}
	raw.Close()

	db, err := InitDB(path)
	if err != nil {
		t.Fatalf("InitDB over legacy schema: %v", err)
	}
	t.Cleanup(func() { db.Close(); WriteDB.Close() })

	if _, err := WriteDB.Exec(
		"UPDATE oidc_clients SET post_logout_redirect_uris = ? WHERE client_id = ?",
		"http://app.local/goodbye", "legacy",
	); err != nil {
		t.Fatalf("column must exist after migrate: %v", err)
	}
	if got := ClientPostLogoutURIs("legacy"); len(got) != 1 || got[0] != "http://app.local/goodbye" {
		t.Fatalf("unexpected whitelist after migrate: %#v", got)
	}
}

func TestSplitURIList(t *testing.T) {
	got := SplitURIList(" http://a/x ,, http://b/y ")
	if len(got) != 2 || got[0] != "http://a/x" || got[1] != "http://b/y" {
		t.Fatalf("unexpected split: %#v", got)
	}
	if got := SplitURIList(""); len(got) != 0 {
		t.Fatalf("empty input must yield empty list, got %#v", got)
	}
}
