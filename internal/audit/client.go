package audit

import (
	"net"
	"net/http"
	"strings"
)

// DeviceInfo 描述用户的设备与环境特征
type DeviceInfo struct {
	OS         string `json:"os"`
	Browser    string `json:"browser"`
	DeviceType string `json:"device_type"` // desktop, mobile, tablet, bot, unknown
	UserAgent  string `json:"user_agent"`
}

// ExtractClientIP 穿透 Cloudflare / 反向代理提取真实客户端 IP
// 优先级:
// 1. CF-Connecting-IP (Cloudflare 官方注入的标准客户端真实 IP)
// 2. True-Client-IP (部分企业级 CDN / Akamai / CF Enterprise)
// 3. X-Forwarded-For（取最右侧有效 IP）
// 4. RemoteAddr 回退
//
// X-Forwarded-For 必须取最右侧：链上每个反代都会把自己看到的对端 IP
// 追加到末尾，最左侧是客户端最初发来的、完全可伪造的值。取首位等于
// 让攻击者任意指定限流桶 / 审计 IP（把桶挪到受害者头上，或把自己
// 的请求记到别人的 IP 名下）。单反代部署时最右侧即真实客户端 IP。
// 本函数本身不做“直连方是否可信”的判断，调用方必须只在直连方是
// 可信反代时才采信转发头（见 internal/admin.clientIP）。
func ExtractClientIP(r *http.Request) string {
	// 1. Cloudflare 专属 Header
	if cfIP := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); cfIP != "" {
		if net.ParseIP(cfIP) != nil {
			return cfIP
		}
	}

	// 2. True-Client-IP
	if tcIP := strings.TrimSpace(r.Header.Get("True-Client-IP")); tcIP != "" {
		if net.ParseIP(tcIP) != nil {
			return tcIP
		}
	}

	// 3. X-Forwarded-For: client, proxy1, proxy2 —— 从右往左取
	// 第一个有效 IP，即离本服务最近的可信反代看到的对端 IP。
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		for i := len(parts) - 1; i >= 0; i-- {
			ip := strings.TrimSpace(parts[i])
			if parsed := net.ParseIP(ip); parsed != nil {
				return ip
			}
		}
	}

	// 4. X-Real-IP
	if realIP := strings.TrimSpace(r.Header.Get("X-Real-IP")); realIP != "" {
		if net.ParseIP(realIP) != nil {
			return realIP
		}
	}

	// 5. RemoteAddr 回退 (host:port)
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	return r.RemoteAddr
}

// ExtractDeviceInfo 从 HTTP 请求中快速解析出操作系统、浏览器与设备形态
func ExtractDeviceInfo(r *http.Request) DeviceInfo {
	ua := r.Header.Get("User-Agent")
	info := DeviceInfo{
		UserAgent:  ua,
		OS:         "Unknown",
		Browser:    "Unknown",
		DeviceType: "desktop",
	}

	if ua == "" {
		return info
	}

	lowerUA := strings.ToLower(ua)

	// 1. 检测设备类型
	if strings.Contains(lowerUA, "ipad") || strings.Contains(lowerUA, "tablet") {
		info.DeviceType = "tablet"
	} else if strings.Contains(lowerUA, "mobile") || strings.Contains(lowerUA, "android") || strings.Contains(lowerUA, "iphone") {
		info.DeviceType = "mobile"
	} else if strings.Contains(lowerUA, "bot") || strings.Contains(lowerUA, "spider") || strings.Contains(lowerUA, "crawl") {
		info.DeviceType = "bot"
	}

	// 2. 检测操作系统 (优先检测 iOS，避免 iPhone 里的 "like mac os x" 误判为 macOS)
	switch {
	case strings.Contains(lowerUA, "iphone") || strings.Contains(lowerUA, "ipad") || strings.Contains(lowerUA, "ios"):
		info.OS = "iOS"
	case strings.Contains(lowerUA, "windows"):
		info.OS = "Windows"
	case strings.Contains(lowerUA, "macintosh") || strings.Contains(lowerUA, "mac os"):
		info.OS = "macOS"
	case strings.Contains(lowerUA, "android"):
		info.OS = "Android"
	case strings.Contains(lowerUA, "linux"):
		info.OS = "Linux"
	}

	// 3. 检测浏览器
	switch {
	case strings.Contains(lowerUA, "micromessenger"):
		info.Browser = "WeChat"
	case strings.Contains(lowerUA, "qq/"):
		info.Browser = "QQ App"
	case strings.Contains(lowerUA, "edg/"):
		info.Browser = "Edge"
	case strings.Contains(lowerUA, "chrome/"):
		info.Browser = "Chrome"
	case strings.Contains(lowerUA, "safari/") && !strings.Contains(lowerUA, "chrome/"):
		info.Browser = "Safari"
	case strings.Contains(lowerUA, "firefox/"):
		info.Browser = "Firefox"
	}

	return info
}
