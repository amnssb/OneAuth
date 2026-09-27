package identity

import "fmt"

// Provider 是身份来源平台的标识。当前只有 qq 一条核销通道（OneBot 群验证码）；
// 接入新平台（如 telegram / wechat / email）时：
//  1. 在此登记 Provider 常量与 Label 展示名；
//  2. 为其实现核销通道，验证通过后调用 session.DefaultManager.VerifyCode
//     把 (provider, code, platformUserID) 绑定为会话身份；
//  3. 在 ProfileFor 的 switch 中登记该平台的 OIDC 资料规则。
//
// sub 语义保持稳定：qq 平台下即 QQ 号，已接入的第三方（Gitea/Nextcloud/
// Grafana）不受影响。
type Identity struct {
	Provider string
	UserID   string
}

const ProviderQQ = "qq"

// QQIdentity 构造 QQ 平台身份；UserID 即 QQ 号。
func QQIdentity(userID string) Identity { return Identity{Provider: ProviderQQ, UserID: userID} }

// Label 返回平台在登录页等界面的展示名；未登记平台直接展示标识本身。
func Label(provider string) string {
	if provider == ProviderQQ {
		return "QQ"
	}
	return provider
}

// Profile 是一个身份在 OIDC 端点（id_token claims 与 /userinfo）中的展示
// 资料。Email 为空表示该平台不提供邮箱语义，接入方应按需降级展示。
type Profile struct {
	Name          string
	Username      string
	Email         string
	EmailVerified bool
	Picture       string
}

func (p Profile) Claims() map[string]any {
	claims := map[string]any{
		"name":               p.Name,
		"preferred_username": p.Username,
		"email_verified":     p.EmailVerified,
	}
	if p.Email != "" {
		claims["email"] = p.Email
	}
	if p.Picture != "" {
		claims["picture"] = p.Picture
	}
	return claims
}

// ProfileFor 返回身份对应的资料规则；新平台在 switch 中登记，未登记平台
// 回落到中性资料（不虚构邮箱/头像）。
func ProfileFor(id Identity) Profile {
	switch id.Provider {
	case ProviderQQ:
		return Profile{
			Name:          "QQ用户_" + id.UserID,
			Username:      id.UserID,
			Email:         id.UserID + "@qq.com",
			EmailVerified: true,
			Picture:       fmt.Sprintf("https://q1.qlogo.cn/g?b=qq&nk=%s&s=640", id.UserID),
		}
	default:
		return Profile{
			Name:     Label(id.Provider) + "用户_" + id.UserID,
			Username: id.UserID,
		}
	}
}
