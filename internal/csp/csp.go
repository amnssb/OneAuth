// Package csp 按页面实际产出的 HTML 计算内容安全策略：把所有内联
// <script> 块与内联事件处理器属性做 sha256 哈希写进 script-src，配合
// 'unsafe-hashes' 让既有页面照常运行，同时让任何新注入的
// <script> / onerror= 之类的标记拿不到匹配的哈希而被浏览器拒绝执行 ——
// 这是 innerHTML 类存储型 XSS 的最后一道兜底。
package csp

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"regexp"
	"strings"
)

var (
	// 内联 script（带 src 的外链脚本不参与哈希，交给 script-src 'self'）
	scriptRe = regexp.MustCompile(`(?is)<script(\s[^>]*)?>(.*?)</script>`)
	// 内联事件处理器属性：onclick="..."、onerror='...'、onload=x 等
	handlerRe = regexp.MustCompile(`(?is)\son[a-z]+\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))`)
	srcAttrRe = regexp.MustCompile(`(?is)\ssrc\s*=`)
)

// Hashes 返回 html 中全部内联脚本与内联事件处理器的 CSP 哈希表达式。
func Hashes(html string) []string {
	seen := make(map[string]bool)
	var out []string
	add := func(src string) {
		if src == "" {
			return
		}
		sum := sha256.Sum256([]byte(src))
		token := "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
		if seen[token] {
			return
		}
		seen[token] = true
		out = append(out, token)
	}

	for _, m := range scriptRe.FindAllStringSubmatch(html, -1) {
		if srcAttrRe.MatchString(m[1]) {
			continue
		}
		add(m[2])
	}
	for _, m := range handlerRe.FindAllStringSubmatch(html, -1) {
		raw := m[1]
		if raw == "" {
			raw = m[2]
		}
		if raw == "" {
			raw = m[3]
		}
		add(decodeAttr(raw))
	}
	return out
}

// decodeAttr 还原属性值的 HTML 实体：浏览器编译内联处理器前会先做实体
// 解码，哈希必须对解码后的文本计算才匹配得上。
func decodeAttr(v string) string {
	if !strings.Contains(v, "&") {
		return v
	}
	r := strings.NewReplacer(
		"&lt;", "<",
		"&gt;", ">",
		"&quot;", `"`,
		"&#39;", "'",
		"&#x27;", "'",
		"&amp;", "&",
	)
	return r.Replace(v)
}

// Policy 依据页面 HTML 生成 CSP。同源资源 + 哈希化的内联脚本，其余一律
// 收紧：禁止外链脚本、禁止 base 劫持、禁止被嵌套（frame-ancestors）。
func Policy(html string) string {
	scriptSrc := "'self'"
	if hashes := Hashes(html); len(hashes) > 0 {
		// 'unsafe-hashes' 让同一串哈希同样适用于内联事件处理器属性
		scriptSrc += " 'unsafe-hashes' " + strings.Join(hashes, " ")
	}
	return strings.Join([]string{
		"default-src 'self'",
		"base-uri 'self'",
		"object-src 'none'",
		"frame-ancestors 'none'",
		"form-action 'self'",
		"script-src " + scriptSrc,
		// 自定义 CSS、style 属性与背景图 URL 由运营配置注入，保持内联可用
		"style-src 'self' 'unsafe-inline'",
		"img-src 'self' data: https:",
		"font-src 'self' data: https:",
		"connect-src 'self'",
		"media-src 'self'",
		"frame-src 'self'",
		"worker-src 'self'",
	}, "; ")
}

// SetHeader 把策略写入响应头。
func SetHeader(w http.ResponseWriter, policy string) {
	w.Header().Set("Content-Security-Policy", policy)
}
