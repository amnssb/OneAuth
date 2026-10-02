package onebot

import (
	"encoding/json"
	"strings"
	"testing"

	"oneauth/internal/session"
)

// processEvent 群绑定回归：验证码必须由绑定群内的消息核销 —— 绑定其他群
// 的会话即使验证码正确也不得被核销，管理统计的累计核销数随之只计一次。
func TestProcessEventVerifiesBoundGroup(t *testing.T) {
	m := session.DefaultManager
	bound, err := m.CreateSession("c_bound", "http://cb.local/cb", "", "", "12345", 60)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	other, err := m.CreateSession("c_other", "http://cb.local/cb", "", "", "99999", 60)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	before := m.Stats().VerifiedTotal
	send := func(groupID int64, text string) {
		t.Helper()
		raw, err := json.Marshal(map[string]any{
			"post_type":    "message",
			"message_type": "group",
			"group_id":     groupID,
			"user_id":      int64(10001),
			"raw_message":  text,
		})
		if err != nil {
			t.Fatalf("marshal event: %v", err)
		}
		processEvent(raw)
	}

	// other 的验证码出现在 bound 的绑定群里：群不匹配，不得核销。
	send(12345, other.VerifyCode)
	if other.Status != session.StatusPending {
		t.Fatal("code sent from a wrong group must stay pending")
	}

	// bound 的验证码在自己的绑定群发送：核销成功。
	send(12345, bound.VerifyCode)
	if bound.Status != session.StatusVerified {
		t.Fatal("code from the bound group must verify")
	}

	if got := m.Stats().VerifiedTotal - before; got != 1 {
		t.Fatalf("VerifiedTotal delta = %d, want 1", got)
	}
}

type mockSender struct {
	sentGroupID string
	sentText    string
}

func (m *mockSender) SendGroupMsg(groupID, text string) error {
	m.sentGroupID = groupID
	m.sentText = text
	return nil
}

func TestOidcStatusCommand(t *testing.T) {
	mock := &mockSender{}
	raw, err := json.Marshal(map[string]any{
		"post_type":    "message",
		"message_type": "group",
		"group_id":     int64(88888),
		"user_id":      int64(10001),
		"raw_message":  "#oidc",
	})
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	processEvent(raw, mock)

	if mock.sentGroupID != "88888" {
		t.Fatalf("expected sentGroupID 88888, got %q", mock.sentGroupID)
	}
	if !strings.Contains(mock.sentText, "✦ OneAuth 运行监控简报 ✦") {
		t.Fatalf("expected report header in sentText, got:\n%s", mock.sentText)
	}
	if !strings.Contains(mock.sentText, "运行时间") {
		t.Fatalf("expected '运行时间' in sentText")
	}
	if !strings.Contains(mock.sentText, "授权请求总数") {
		t.Fatalf("expected '授权请求总数' in sentText")
	}
	if !strings.Contains(mock.sentText, "验证码核销量") {
		t.Fatalf("expected '验证码核销量' in sentText")
	}
}

func TestBuildStatusReport(t *testing.T) {
	report := BuildStatusReport()
	if !strings.Contains(report, "OneAuth") {
		t.Fatalf("expected 'OneAuth' in report")
	}
	if !strings.Contains(report, "鉴权核销成功率") {
		t.Fatalf("expected '鉴权核销成功率' in report")
	}
}
