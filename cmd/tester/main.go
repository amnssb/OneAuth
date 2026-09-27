// 模拟 NapCatQQ 向 OneAuth 推送群验证码消息的自动化测试脚本
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

const (
	wsToken      = "2rZY778PKgCO6ljZ"
	targetGroup  = 309623044
	testQQ       = 100000001
	clientID     = "oa_1M6NAtTrYITbvmul"
	clientSecret = "iuH6nsEJQs93H0hEZUsAkWyLQsS0cW3A9fUU_Zn4Gp8="
)

// oneAuthHost 可用环境变量 ONEAUTH_HOST 覆盖（默认 localhost:9000），
// 便于在测试端口上冒烟。
func resolveHost() string {
	if h := os.Getenv("ONEAUTH_HOST"); h != "" {
		return h
	}
	return "localhost:9000"
}

func main() {
	oneAuthHost := resolveHost()
	fmt.Println("==================================================")
	fmt.Println("🚀 OneAuth 全链路端到端模拟核验测试")
	fmt.Println("==================================================")

	// 1. 发起 OIDC 授权请求，获取登录页与验证码
	fmt.Println("\n[步骤 1] 模拟业务系统发起 /authorize 请求...")
	authURL := fmt.Sprintf("http://%s/authorize?client_id=%s&redirect_uri=%s&response_type=code&scope=openid+profile+email",
		oneAuthHost, clientID, url.QueryEscape("http://localhost:8080/callback"))

	// 禁止自动跟随 302 重定向以提取 session_id
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Get(authURL)
	if err != nil {
		log.Fatalf("❌ 请求 /authorize 失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		log.Fatalf("❌ /authorize 期望返回 302，实际返回 %d: %s", resp.StatusCode, string(body))
	}

	loc := resp.Header.Get("Location")
	fmt.Printf("✓ 收到重定向地址: %s\n", loc)

	u, _ := url.Parse(loc)
	sessionID := u.Query().Get("session_id")
	if sessionID == "" {
		log.Fatalf("❌ 重定向地址未包含 session_id 参数！")
	}
	fmt.Printf("✓ 成功提取会话 ID (SessionID): %s\n", sessionID)

	// 2. 模拟浏览器请求 /login 获取页面内渲染的 6 位验证码
	fmt.Println("\n[步骤 2] 获取登录页并解析 6 位群验证码...")
	loginResp, err := http.Get(fmt.Sprintf("http://%s%s", oneAuthHost, loc))
	if err != nil {
		log.Fatalf("❌ 请求登录页失败: %v", err)
	}
	defer loginResp.Body.Close()

	loginBodyBytes, _ := io.ReadAll(loginResp.Body)
	loginHTML := string(loginBodyBytes)

	// 从 HTML 中抓取验证码
	verifyCode := extractCodeFromHTML(loginHTML)
	if verifyCode == "" {
		log.Fatalf("❌ 无法从登录页 HTML 中提取验证码！")
	}
	fmt.Printf("🎯 捕获当前会话的 6 位高熵验证码: 【 %s 】\n", verifyCode)

	// 3. 模拟浏览器挂载 SSE 长连接监听核销状态
	fmt.Println("\n[步骤 3] 模拟浏览器挂载 SSE 长连接 (/api/session/stream)...")
	sseURL := fmt.Sprintf("http://%s/api/session/stream?session_id=%s", oneAuthHost, sessionID)
	sseReq, _ := http.NewRequest("GET", sseURL, nil)
	sseResp, err := http.DefaultClient.Do(sseReq)
	if err != nil {
		log.Fatalf("❌ 建立 SSE 连接失败: %v", err)
	}
	defer sseResp.Body.Close()
	fmt.Println("✓ SSE 实时通道已就绪，正在阻塞等待核销事件...")

	sseDone := make(chan string)
	go func() {
		buf := make([]byte, 1024)
		for {
			n, err := sseResp.Body.Read(buf)
			if n > 0 {
				msg := string(buf[:n])
				if strings.Contains(msg, "verified") {
					sseDone <- msg
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	// 4. 模拟 NapCatQQ 建立反向 WebSocket 并推送群消息事件
	fmt.Println("\n[步骤 4] 模拟 NapCatQQ 发起反向 WebSocket 连接至 OneAuth...")
	wsURL := fmt.Sprintf("ws://%s/ws/onebot?access_token=%s", oneAuthHost, wsToken)
	wsConn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		log.Fatalf("❌ 反向 WebSocket 连入失败: %v", err)
	}
	defer wsConn.Close()
	fmt.Println("✓ WebSocket 握手成功，模拟机器人已上线！")

	time.Sleep(500 * time.Millisecond)

	// 构建 OneBot v11 标准群消息报文
	fmt.Printf("📤 正在向 OneAuth 注入群消息事件 [群号: %d | QQ: %d | 消息: %s]...\n", targetGroup, testQQ, verifyCode)
	mockEvent := map[string]interface{}{
		"post_type":    "message",
		"message_type": "group",
		"sub_type":     "normal",
		"group_id":     targetGroup,
		"user_id":      testQQ,
		"raw_message":  verifyCode,
		"message": []map[string]interface{}{
			{
				"type": "text",
				"data": map[string]interface{}{
					"text": verifyCode,
				},
			},
		},
	}
	eventBytes, _ := json.Marshal(mockEvent)
	if err := wsConn.WriteMessage(websocket.TextMessage, eventBytes); err != nil {
		log.Fatalf("❌ 推送群消息失败: %v", err)
	}

	// 5. 校验 SSE 是否接收到跳转指令
	fmt.Println("\n[步骤 5] 等待 OneAuth 状态机核销与前端推送...")
	select {
	case ssePayload := <-sseDone:
		fmt.Println("🎉 【核销成功！】浏览器 SSE 实时通道捕获到服务端推送:")
		fmt.Printf("   %s\n", strings.TrimSpace(ssePayload))
	case <-time.After(5 * time.Second):
		log.Fatalf("❌ 等待超时！5秒内未收到 SSE verified 事件推送")
	}

	// 6. 兑换授权码并获取最终的 OIDC ID Token
	fmt.Println("\n[步骤 6] 模拟换取授权码与最终的 OIDC 令牌 (/token)...")
	// 调用 callback 接口获取 code
	callbackResp, err := client.Get(fmt.Sprintf("http://%s/api/session/callback?session_id=%s", oneAuthHost, sessionID))
	if err != nil {
		log.Fatalf("❌ 请求 session callback 失败: %v", err)
	}
	defer callbackResp.Body.Close()

	finalRedirect := callbackResp.Header.Get("Location")
	fmt.Printf("✓ 浏览器最终回调跳转: %s\n", finalRedirect)
	finalU, _ := url.Parse(finalRedirect)
	authCode := finalU.Query().Get("code")
	fmt.Printf("✓ 成功兑换 AuthCode: %s\n", authCode)

	// 调用 /token 接口兑换 RS256 JWT
	tokenForm := url.Values{}
	tokenForm.Set("grant_type", "authorization_code")
	tokenForm.Set("code", authCode)
	tokenForm.Set("client_id", clientID)
	tokenForm.Set("client_secret", clientSecret)

	tokenResp, err := http.PostForm(fmt.Sprintf("http://%s/token", oneAuthHost), tokenForm)
	if err != nil {
		log.Fatalf("❌ 请求 /token 失败: %v", err)
	}
	defer tokenResp.Body.Close()

	tokenBody, _ := io.ReadAll(tokenResp.Body)
	fmt.Println("\n==================================================")
	fmt.Println("🎊 恭喜！全链路验证闭环完成！")
	fmt.Printf("OIDC Token 响应结果:\n%s\n", string(tokenBody))
	fmt.Println("==================================================")
}

func extractCodeFromHTML(html string) string {
	startTag := "id=\"verifyCode\">"
	idx := strings.Index(html, startTag)
	if idx == -1 {
		return ""
	}
	idx += len(startTag)
	endIdx := strings.Index(html[idx:], "<")
	if endIdx == -1 {
		return ""
	}
	return strings.TrimSpace(html[idx : idx+endIdx])
}
