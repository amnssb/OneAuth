package oidc

import (
	"crypto/rsa"
	"path/filepath"
	"testing"
	"time"

	"oneauth/internal/database"
)

func initKeyTestDB(t *testing.T) {
	t.Helper()
	if _, err := database.InitDB(filepath.Join(t.TempDir(), "keys.db")); err != nil {
		t.Fatalf("init db: %v", err)
	}
	t.Cleanup(func() { database.DB.Close(); database.WriteDB.Close() })
	// 每个用例独立进程内缓存，避免不同 DB 之间串味。
	tenantKeys.mu.Lock()
	tenantKeys.private = map[string]*rsa.PrivateKey{}
	tenantKeys.kid = map[string]string{}
	tenantKeys.mu.Unlock()
}

// TenantSigningKey 首次生成并落库，二次调用命中缓存返回同一把密钥。
func TestTenantSigningKeyStableAcrossCalls(t *testing.T) {
	initKeyTestDB(t)

	k1, kid1, err := TenantSigningKey("acme")
	if err != nil {
		t.Fatalf("first load: %v", err)
	}
	if kid1 == "" {
		t.Fatal("kid must not be empty")
	}
	k2, kid2, err := TenantSigningKey("acme")
	if err != nil {
		t.Fatalf("second load: %v", err)
	}
	if k1 != k2 || kid1 != kid2 {
		t.Fatal("repeated TenantSigningKey must return the same cached key")
	}

	// 不同租户必须是不同的密钥/kid。
	_, kidOther, err := TenantSigningKey("globex")
	if err != nil {
		t.Fatalf("other tenant: %v", err)
	}
	if kidOther == kid1 {
		t.Fatal("different tenants must have different kids")
	}
}

// 轮换：旧密钥退休但仍在宽限期 JWKS 里，新密钥成为在用密钥，kid 变化。
func TestRotateTenantKeyKeepsOldInGrace(t *testing.T) {
	initKeyTestDB(t)

	_, oldKid, err := TenantSigningKey("acme")
	if err != nil {
		t.Fatalf("initial key: %v", err)
	}

	newKid, err := RotateTenantKey("acme")
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if newKid == oldKid {
		t.Fatal("rotation must produce a new kid")
	}

	// 在用密钥应是新 kid。
	if row, ok := database.ActiveTenantKey("acme"); !ok || row.Kid != newKid {
		t.Fatalf("active key should be new kid, got %+v ok=%v", row, ok)
	}

	// 宽限期内 JWKS 同时公布新旧两把 key。
	entries, err := tenantJWKSEntries("acme")
	if err != nil {
		t.Fatalf("jwks entries: %v", err)
	}
	seen := map[string]bool{}
	for _, e := range entries {
		seen[e.kid] = true
	}
	if !seen[oldKid] || !seen[newKid] {
		t.Fatalf("both kids must appear in JWKS within grace, got %v", seen)
	}

	// userinfo 验签能按 kid 找到新旧两把公钥。
	if _, ok := tenantPublicKeyByKid("acme", oldKid); !ok {
		t.Fatal("old kid must remain resolvable in grace period")
	}
	if _, ok := tenantPublicKeyByKid("acme", newKid); !ok {
		t.Fatal("new kid must be resolvable")
	}
	// 跨租户 kid 不可解析。
	if _, ok := tenantPublicKeyByKid("globex", newKid); ok {
		t.Fatal("kid from another tenant must not resolve")
	}
}

// 宽限期过后清理：退休且超期的旧密钥被物理删除，不再出现在 JWKS。
func TestPurgeExpiredTenantKeys(t *testing.T) {
	initKeyTestDB(t)

	_, oldKid, _ := TenantSigningKey("acme")
	if _, err := RotateTenantKey("acme"); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	// 手动把旧 key 的 retired_at 推到宽限期之外，再清理。
	past := time.Now().Add(-(keyRotationGrace + time.Hour)).UTC().Format("2006-01-02 15:04:05")
	if _, err := database.WriteDB.Exec(
		"UPDATE tenant_keys SET retired_at = ? WHERE slug = ? AND kid = ?", past, "acme", oldKid,
	); err != nil {
		t.Fatalf("age old key: %v", err)
	}
	if err := database.PurgeExpiredTenantKeys("acme", keyRotationGrace); err != nil {
		t.Fatalf("purge: %v", err)
	}
	if _, ok := tenantPublicKeyByKid("acme", oldKid); ok {
		t.Fatal("expired retired key must be purged from JWKS")
	}
}
