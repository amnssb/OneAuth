package onebot

import (
	"encoding/json"
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
