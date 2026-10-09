package csp

import (
	"strings"
	"testing"
)

// 页面既有的内联脚本与事件处理器必须全部被哈希覆盖（否则策略一上线就
// 白屏），同时策略里不得出现 'unsafe-inline' 这种形同虚设的放行。
func TestPolicyCoversInlineScriptAndHandlers(t *testing.T) {
	html := `<html><body>
		<div onclick="copyCode()">copy</div>
		<input onkeydown="if(event.key==='Enter')go()">
		<script>
		const a = 1;
		</script>
		<script src="/static/app.js"></script>
		</body></html>`

	policy := Policy(html)
	if !strings.Contains(policy, "script-src 'self' 'unsafe-hashes'") {
		t.Fatalf("expected hashed script-src, got: %s", policy)
	}
	if strings.Contains(policy, "script-src 'self' 'unsafe-inline'") {
		t.Fatalf("unsafe-inline must never be allowed: %s", policy)
	}
	if !strings.Contains(policy, "frame-ancestors 'none'") || !strings.Contains(policy, "base-uri 'self'") {
		t.Fatalf("missing hardening directives: %s", policy)
	}

	hashes := Hashes(html)
	// 两个内联 script/处理器 + onkeydown，外链脚本不参与
	if len(hashes) < 3 {
		t.Fatalf("expected >=3 hashes, got %d: %v", len(hashes), hashes)
	}
	for _, h := range hashes {
		if !strings.Contains(policy, h) {
			t.Fatalf("hash %s missing from policy: %s", h, policy)
		}
	}
}

// 注入的新脚本拿不到既有哈希，因此会被浏览器拒绝执行 —— 这正是审计日志
// 这类 innerHTML 渲染点的最后一道兜底。
func TestInjectedScriptNotCovered(t *testing.T) {
	page := Policy(`<script>legit();</script>`)
	injected := Hashes(`<img src=x onerror=alert(1)>`)
	if len(injected) != 1 {
		t.Fatalf("expected one handler hash, got %v", injected)
	}
	if strings.Contains(page, injected[0]) {
		t.Fatal("injected handler hash must not be part of the page policy")
	}
}

func TestDecodeAttr(t *testing.T) {
	if got := decodeAttr("a &amp; b &lt;c&gt; &quot;d&quot; &#39;e&#39;"); got != `a & b <c> "d" 'e'` {
		t.Fatalf("unexpected decode: %q", got)
	}
	if got := decodeAttr("no-entities"); got != "no-entities" {
		t.Fatalf("unexpected decode: %q", got)
	}
}
