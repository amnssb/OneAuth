package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"sync"
	"time"

	"oneauth/internal/database"
)

// keyRotationGrace 是密钥轮换后旧公钥继续留在 JWKS 中的宽限期：轮换发生
// 时可能还有用旧密钥签发、尚未过期的 id_token 在流转，宽限期内下游依然
// 能验签通过；超过宽限期后 PurgeExpiredTenantKeys 才会真正物理删除。
const keyRotationGrace = 7 * 24 * time.Hour

// tenantKeyCache 是按 issuer_slug 缓存的当前在用签名私钥，避免每次签发
// /{slug}/token 都要访问 SQLite 并重新解析 PEM。
type tenantKeyCache struct {
	mu      sync.RWMutex
	private map[string]*rsa.PrivateKey // slug -> 当前在用私钥
	kid     map[string]string          // slug -> 当前在用 kid
}

var tenantKeys = &tenantKeyCache{
	private: make(map[string]*rsa.PrivateKey),
	kid:     make(map[string]string),
}

func encodePrivatePEM(key *rsa.PrivateKey) string {
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}))
}

func decodePrivatePEM(data string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(data))
	if block == nil {
		return nil, fmt.Errorf("无法解析 PEM 私钥块")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// TenantSigningKey 返回某个 issuer_slug 当前在用的 RSA 私钥与 kid：
// SQLite 里已有在用密钥则加载，否则惰性生成一把新的 RSA-2048 并持久化
// （覆盖新建应用与 v3 自动回填 slug 但还没密钥这两种情况）。首次加载后
// 缓存在内存中。
func TenantSigningKey(slug string) (*rsa.PrivateKey, string, error) {
	tenantKeys.mu.RLock()
	if pk, ok := tenantKeys.private[slug]; ok {
		kid := tenantKeys.kid[slug]
		tenantKeys.mu.RUnlock()
		return pk, kid, nil
	}
	tenantKeys.mu.RUnlock()

	tenantKeys.mu.Lock()
	defer tenantKeys.mu.Unlock()
	// 拿写锁后二次确认：可能在等锁期间已被另一个请求加载。
	if pk, ok := tenantKeys.private[slug]; ok {
		return pk, tenantKeys.kid[slug], nil
	}

	if row, ok := database.ActiveTenantKey(slug); ok {
		pk, err := decodePrivatePEM(row.PrivatePEM)
		if err != nil {
			return nil, "", fmt.Errorf("解析租户 %s 密钥失败: %w", slug, err)
		}
		tenantKeys.private[slug] = pk
		tenantKeys.kid[slug] = row.Kid
		return pk, row.Kid, nil
	}

	pk, kid, err := generateAndStoreTenantKey(slug)
	if err != nil {
		return nil, "", err
	}
	tenantKeys.private[slug] = pk
	tenantKeys.kid[slug] = kid
	return pk, kid, nil
}

func generateAndStoreTenantKey(slug string) (*rsa.PrivateKey, string, error) {
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, "", fmt.Errorf("生成租户 %s RSA 密钥失败: %w", slug, err)
	}
	kid := computeKID(&pk.PublicKey)
	if err := database.InsertTenantKey(slug, kid, encodePrivatePEM(pk)); err != nil {
		return nil, "", fmt.Errorf("持久化租户 %s 密钥失败: %w", slug, err)
	}
	return pk, kid, nil
}

// RotateTenantKey 把某租户当前在用密钥标记为退休（宽限期内仍出现在
// JWKS 里），并生成、持久化一把全新的在用密钥；顺带清理该租户已过宽限
// 期的历史密钥。返回新密钥的 kid。
func RotateTenantKey(slug string) (newKid string, err error) {
	tenantKeys.mu.Lock()
	defer tenantKeys.mu.Unlock()

	if err := database.RetireActiveTenantKeys(slug); err != nil {
		return "", fmt.Errorf("退休旧密钥失败: %w", err)
	}
	pk, kid, err := generateAndStoreTenantKey(slug)
	if err != nil {
		return "", err
	}
	tenantKeys.private[slug] = pk
	tenantKeys.kid[slug] = kid

	if err := database.PurgeExpiredTenantKeys(slug, keyRotationGrace); err != nil {
		// 清理失败不影响本次轮换结果，记日志即可，下次轮换/JWKS 请求会
		// 自然收敛（宽限期判断本身不依赖这次清理是否成功）。
		log.Printf("[OIDC] 清理租户 %s 过期密钥失败（不影响本次轮换）: %v", slug, err)
	}
	return kid, nil
}

// jwkEntry 是渲染 JWKS 文档时需要的最小信息。
type jwkEntry struct {
	kid string
	pub *rsa.PublicKey
}

// tenantJWKSEntries 返回某租户当前应该在 JWKS 中公布的全部公钥：在用
// 密钥 + 宽限期内的退休密钥，按创建时间新到旧排列。
func tenantJWKSEntries(slug string) ([]jwkEntry, error) {
	rows, err := database.TenantJWKSKeys(slug, keyRotationGrace)
	if err != nil {
		return nil, err
	}
	out := make([]jwkEntry, 0, len(rows))
	for _, row := range rows {
		pk, err := decodePrivatePEM(row.PrivatePEM)
		if err != nil {
			log.Printf("[OIDC] 租户 %s 密钥 kid=%s 解析失败，已跳过: %v", slug, row.Kid, err)
			continue
		}
		out = append(out, jwkEntry{kid: row.Kid, pub: &pk.PublicKey})
	}
	return out, nil
}

// tenantPublicKeyByKid 在某租户当前公布的密钥集合（在用 + 宽限期内）里
// 按 kid 查找公钥，供 /{slug}/userinfo 验签使用；跨租户或已彻底过期的
// kid 一律查不到，天然拒绝跨租户令牌重放。
func tenantPublicKeyByKid(slug, kid string) (*rsa.PublicKey, bool) {
	entries, err := tenantJWKSEntries(slug)
	if err != nil {
		return nil, false
	}
	for _, e := range entries {
		if e.kid == kid {
			return e.pub, true
		}
	}
	return nil, false
}
