package identity

import "testing"

// qq 平台资料规则：sub 语义即 QQ 号，邮箱/头像按现有第三方接入约定生成。
func TestProfileForQQ(t *testing.T) {
	p := ProfileFor(QQIdentity("10001"))
	if p.Name != "QQ用户_10001" || p.Username != "10001" {
		t.Fatalf("unexpected qq profile: %+v", p)
	}
	if p.Email != "10001@qq.com" || !p.EmailVerified || p.Picture == "" {
		t.Fatalf("unexpected qq profile: %+v", p)
	}

	claims := p.Claims()
	if claims["email"] != "10001@qq.com" || claims["picture"] == nil || claims["email_verified"] != true {
		t.Fatalf("unexpected qq claims: %v", claims)
	}
}

// 未登记平台必须回落到中性资料：不虚构邮箱与头像，避免把 QQ 语义泄漏到
// 其它平台身份上。
func TestProfileForUnknownProvider(t *testing.T) {
	p := ProfileFor(Identity{Provider: "telegram", UserID: "42"})
	if p.Name != "telegram用户_42" || p.Username != "42" {
		t.Fatalf("unexpected fallback profile: %+v", p)
	}
	if p.Email != "" || p.Picture != "" || p.EmailVerified {
		t.Fatalf("fallback profile must not fabricate email/picture: %+v", p)
	}

	claims := p.Claims()
	if _, ok := claims["email"]; ok {
		t.Fatalf("fallback claims must omit email: %v", claims)
	}
	if _, ok := claims["picture"]; ok {
		t.Fatalf("fallback claims must omit picture: %v", claims)
	}
}

func TestLabel(t *testing.T) {
	if Label(ProviderQQ) != "QQ" || Label("wechat") != "wechat" {
		t.Fatal("unexpected label mapping")
	}
}
