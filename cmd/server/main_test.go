package main

import (
	"strings"
	"testing"

	"oneauth/internal/csp"
)

// Demo 客户端密钥：环境变量优先；未配置时必须生成随机值，
// 绝不回退到源码里的公开默认值。
func TestResolveDemoClientSecret(t *testing.T) {
	t.Setenv("DEMO_CLIENT_SECRET", "fixed-secret-from-env")
	if got := resolveDemoClientSecret(); got != "fixed-secret-from-env" {
		t.Fatalf("env secret must win, got %q", got)
	}

	t.Setenv("DEMO_CLIENT_SECRET", "")
	first := resolveDemoClientSecret()
	if first == "" {
		t.Fatal("random secret must not be empty")
	}
	if first == "demo_secret_888888" {
		t.Fatal("published default secret must never be used")
	}
	second := resolveDemoClientSecret()
	if first == second {
		t.Fatal("unconfigured secret must be regenerated each start")
	}
}

// 管理台 CSP 必须覆盖页面自带的内联脚本与事件处理器（否则上线即白屏），
// 同时注入的新脚本拿不到哈希。
func TestAdminCSPCoversInlineScript(t *testing.T) {
	raw := mustReadTemplate("admin.html")
	policy := csp.Policy(raw)

	if !strings.Contains(policy, "script-src 'self' 'unsafe-hashes'") {
		t.Fatalf("expected hashed script-src, got: %s", policy)
	}
	if !strings.Contains(policy, "'sha256-") {
		t.Fatalf("policy must carry inline script hashes: %s", policy)
	}
	if strings.Contains(policy, "script-src 'self' 'unsafe-inline'") {
		t.Fatalf("script must not be wide open: %s", policy)
	}
	for _, h := range csp.Hashes(raw) {
		if !strings.Contains(policy, h) {
			t.Fatalf("page hash %s missing from policy", h)
		}
	}

	injected := csp.Hashes(`<img src=x onerror=alert(1)>`)
	if len(injected) != 1 || strings.Contains(policy, injected[0]) {
		t.Fatal("injected handler must not be covered by the page policy")
	}
}
