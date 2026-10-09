package onebot

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"oneauth/internal/database"
	"oneauth/internal/session"
)

func initSecurityTestDB(t *testing.T) {
	t.Helper()
	if _, err := database.InitDB(filepath.Join(t.TempDir(), "ws.db")); err != nil {
		t.Fatalf("init db: %v", err)
	}
	t.Cleanup(func() { database.WriteDB.Close(); database.DB.Close() })
}

func doWS(token, remoteAddr string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/ws/onebot", nil)
	req.RemoteAddr = remoteAddr
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	HandleWebSocket(rec, req)
	return rec
}

// 未配置 onebot_token 时必须 fail-closed：历史上空 token 直接放行，
// 等于 /ws/onebot 对公网敞开认证绕过入口。
func TestWebSocketFailClosedWithoutToken(t *testing.T) {
	initSecurityTestDB(t)
	if err := database.SetSetting("onebot_token", ""); err != nil {
		t.Fatalf("clear token: %v", err)
	}
	if rec := doWS("", "203.0.113.10:40000"); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("empty token must yield 503, got %d", rec.Code)
	}
}

func TestWebSocketTokenEnforced(t *testing.T) {
	initSecurityTestDB(t)
	if err := database.SetSetting("onebot_token", "unit-test-secret"); err != nil {
		t.Fatalf("set token: %v", err)
	}
	if rec := doWS("wrong", "203.0.113.10:40000"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token must yield 401, got %d", rec.Code)
	}
	// 正确 token：认证通过（非 401/503），随后因缺少 WS 握手头在 Upgrade 处 400
	if rec := doWS("unit-test-secret", "203.0.113.10:40000"); rec.Code == http.StatusUnauthorized || rec.Code == http.StatusServiceUnavailable {
		t.Fatalf("valid token must pass auth, got %d", rec.Code)
	}
}

func TestWebSocketIPAllowlist(t *testing.T) {
	initSecurityTestDB(t)
	if err := database.SetSetting("onebot_token", "unit-test-secret"); err != nil {
		t.Fatalf("set token: %v", err)
	}
	if err := database.SetSetting("onebot_ws_ip_allowlist", "203.0.113.7, 10.0.0.0/8"); err != nil {
		t.Fatalf("set allowlist: %v", err)
	}
	t.Cleanup(func() { _ = database.SetSetting("onebot_ws_ip_allowlist", "") })

	if rec := doWS("unit-test-secret", "198.51.100.99:40000"); rec.Code != http.StatusForbidden {
		t.Fatalf("source outside allowlist must yield 403, got %d", rec.Code)
	}
	if rec := doWS("unit-test-secret", "203.0.113.7:40000"); rec.Code == http.StatusForbidden {
		t.Fatalf("allowlisted IP must pass, got %d", rec.Code)
	}
	if rec := doWS("unit-test-secret", "10.1.2.3:40000"); rec.Code == http.StatusForbidden {
		t.Fatalf("allowlisted CIDR must pass, got %d", rec.Code)
	}
}

// v12 上游给的是原始字符串：非数字（含 HTML 注入载荷）必须被丢弃，
// 否则会一路流进会话身份与审计日志，最终在管理台触发存储型 XSS。
func TestNumericIDRejectsInjection(t *testing.T) {
	cases := []struct {
		in   interface{}
		want string
		ok   bool
	}{
		{float64(10001), "10001", true},
		{"10001", "10001", true},
		{" 88888 ", "88888", true},
		{"<img src=x onerror=alert(1)>", "", false},
		{"10001<script>", "", false},
		{"-1", "", false},
		{"12.5", "", false},
		{"", "", false},
		{nil, "", false},
		{true, "", false},
	}
	for _, c := range cases {
		got, ok := numericID(c.in)
		if ok != c.ok || got != c.want {
			t.Fatalf("numericID(%#v) = (%q, %v), want (%q, %v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestProcessEventRejectsNonNumericV12Identity(t *testing.T) {
	m := session.DefaultManager
	sess, err := m.CreateSession("c_v12", "http://cb.local/cb", "", "", "424242", 60)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	raw, err := json.Marshal(map[string]any{
		"type":        "message",
		"detail_type": "group",
		"group_id":    "424242",
		"user_id":     "<img src=x onerror=alert(1)>",
		"alt_message": sess.VerifyCode,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	processEvent(raw)
	if sess.Status != session.StatusPending {
		t.Fatal("non-numeric v12 user_id must be dropped, not verified")
	}

	// 合法数字字符串的 v12 身份仍应正常核销
	rawOK, err := json.Marshal(map[string]any{
		"type":        "message",
		"detail_type": "group",
		"group_id":    "424242",
		"user_id":     "10001",
		"alt_message": sess.VerifyCode,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	processEvent(rawOK)
	if sess.Status != session.StatusVerified {
		t.Fatal("numeric v12 identity must verify normally")
	}
}

type fakeMemberSender struct {
	inGroup bool
	queries int
}

func (f *fakeMemberSender) SendGroupMsg(groupID, text string) error { return nil }

func (f *fakeMemberSender) CheckGroupMember(groupID, userID string) (bool, error) {
	f.queries++
	return f.inGroup, nil
}

// 开启群成员二次核验后，机器人反查不到“该 QQ 在群内”就不得核销。
func TestMemberVerificationGate(t *testing.T) {
	initSecurityTestDB(t)
	if err := database.SetSetting("onebot_verify_member", "true"); err != nil {
		t.Fatalf("enable verify: %v", err)
	}
	t.Cleanup(func() { _ = database.SetSetting("onebot_verify_member", "false") })

	m := session.DefaultManager
	sess, err := m.CreateSession("c_member", "http://cb.local/cb", "", "", "515151", 60)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	event := func() []byte {
		raw, err := json.Marshal(map[string]any{
			"post_type":    "message",
			"message_type": "group",
			"group_id":     float64(515151),
			"user_id":      float64(10001),
			"raw_message":  sess.VerifyCode,
		})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return raw
	}

	sender := &fakeMemberSender{inGroup: false}
	processEvent(event(), sender)
	if sess.Status != session.StatusPending {
		t.Fatal("membership negative must block verification")
	}
	if sender.queries == 0 {
		t.Fatal("expected get_group_member_info to be queried")
	}

	sender.inGroup = true
	processEvent(event(), sender)
	if sess.Status != session.StatusVerified {
		t.Fatal("membership positive must allow verification")
	}
}

// 关闭二次核验时，普通 Sender（不实现 MemberChecker）照常工作。
func TestMemberVerificationOffByDefault(t *testing.T) {
	initSecurityTestDB(t)
	if got := database.GetSetting("onebot_verify_member", "false"); got == "true" {
		t.Fatal("member verification must default to off")
	}

	m := session.DefaultManager
	sess, err := m.CreateSession("c_off", "http://cb.local/cb", "", "", "616161", 60)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	raw, err := json.Marshal(map[string]any{
		"post_type":    "message",
		"message_type": "group",
		"group_id":     float64(616161),
		"user_id":      float64(10001),
		"raw_message":  sess.VerifyCode,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	processEvent(raw)
	if sess.Status != session.StatusVerified {
		t.Fatal("verification must work without member check when disabled")
	}
}

// 验证码尝试限流：同一 QQ 超过阈值后被拒，换 QQ/换群不受牵连。
func TestVerifyAttemptRateLimit(t *testing.T) {
	group, user := "g-rl", "u-rl"
	for i := 0; i < verifyMaxUser; i++ {
		if !allowVerifyAttempt(group, user) {
			t.Fatalf("attempt %d should be allowed", i+1)
		}
	}
	if allowVerifyAttempt(group, user) {
		t.Fatal("user must be limited after exceeding threshold")
	}
	if !allowVerifyAttempt(group, "u-rl-other") {
		t.Fatal("another user must not be affected")
	}

	// 群维度：换着用户打满群额度后整群被限
	g2 := "g-rl-flood"
	for i := 0; i < verifyMaxGroup; i++ {
		if !allowVerifyAttempt(g2, "u-flood-"+string(rune('a'+i%26))+"-"+string(rune('a'+i/26))) {
			t.Fatalf("group flood attempt %d should pass", i+1)
		}
	}
	if allowVerifyAttempt(g2, "u-fresh") {
		t.Fatal("group must be limited after exceeding threshold")
	}
}
