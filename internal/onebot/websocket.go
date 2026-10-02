package onebot

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"oneauth/internal/database"
	"oneauth/internal/identity"
	"oneauth/internal/session"
	"oneauth/internal/version"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

var codeRegex = regexp.MustCompile("^[2-9A-HJ-NP-Z]{6}$")

// Unanchored twin of codeRegex: an admin often says "验证码：XXXXXX" or sends
// the code after a mention, so the code is searched for rather than required
// to be the whole message. It still has to exist in the code index to count,
// which is where the real check happens.
var codeSearchRegex = regexp.MustCompile(`[2-9A-HJ-NP-Z]{6}`)
var cqRegex = regexp.MustCompile(`\[CQ:[^\]]+\]`)

const (
	// 单帧上限，防止恶意超大报文占用内存
	wsReadLimit = 1 << 20
	// 每连接事件队列上限：处理是有序单消费者，队列满说明机器人流量异常突增，
	// 此时丢弃新事件（验证码消息可由用户重发）而不是无界堆积内存。
	eventQueueLen = 256
)

// Sender 定义 OneBot 群消息回发接口
type Sender interface {
	SendGroupMsg(groupID, text string) error
}

type wsClient struct {
	conn    *websocket.Conn
	writeMu sync.Mutex
	isV12   atomic.Bool
}

func newWSClient(conn *websocket.Conn) *wsClient {
	return &wsClient{conn: conn}
}

func (c *wsClient) SendGroupMsg(groupID, text string) error {
	if c == nil || c.conn == nil {
		return nil
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if c.isV12.Load() {
		payload := map[string]any{
			"action": "send_message",
			"params": map[string]any{
				"detail_type": "group",
				"group_id":    groupID,
				"message": []map[string]any{
					{"type": "text", "data": map[string]any{"text": text}},
				},
			},
		}
		return c.conn.WriteJSON(payload)
	}

	var gid any = groupID
	if n, err := strconv.ParseInt(groupID, 10, 64); err == nil {
		gid = n
	}
	payload := map[string]any{
		"action": "send_group_msg",
		"params": map[string]any{
			"group_id": gid,
			"message":  text,
		},
	}
	return c.conn.WriteJSON(payload)
}

var (
	clientsMu     sync.RWMutex
	activeClients []*wsClient
	startTime     = time.Now()

	cooldownMu    sync.Mutex
	groupCooldown = make(map[string]time.Time)
)

func registerClient(c *wsClient) {
	clientsMu.Lock()
	activeClients = append(activeClients, c)
	clientsMu.Unlock()
}

func unregisterClient(c *wsClient) {
	clientsMu.Lock()
	defer clientsMu.Unlock()
	for i, item := range activeClients {
		if item == c {
			activeClients = append(activeClients[:i], activeClients[i+1:]...)
			break
		}
	}
}

func getActiveSender() Sender {
	clientsMu.RLock()
	defer clientsMu.RUnlock()
	if len(activeClients) > 0 {
		return activeClients[len(activeClients)-1]
	}
	return nil
}

func checkGroupCooldown(groupID string, cd time.Duration) bool {
	cooldownMu.Lock()
	defer cooldownMu.Unlock()
	now := time.Now()
	if last, exists := groupCooldown[groupID]; exists && now.Sub(last) < cd {
		return false
	}
	groupCooldown[groupID] = now
	return true
}

func formatUptime(d time.Duration) string {
	sec := int64(d.Seconds())
	if sec < 0 {
		sec = 0
	}
	days := sec / 86400
	hours := (sec % 86400) / 3600
	mins := (sec % 3600) / 60
	secs := sec % 60

	if days > 0 {
		return fmt.Sprintf("%d天 %d小时 %d分", days, hours, mins)
	}
	if hours > 0 {
		return fmt.Sprintf("%d小时 %d分 %d秒", hours, mins, secs)
	}
	if mins > 0 {
		return fmt.Sprintf("%d分 %d秒", mins, secs)
	}
	return fmt.Sprintf("%d秒", secs)
}

// BuildStatusReport 组装 #oidc 指令回复的运行监控简报
func BuildStatusReport() string {
	uptimeStr := formatUptime(time.Since(startTime))
	verInfo := version.Get()
	stats := session.DefaultManager.Stats()

	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	heapMB := math.Round(float64(ms.HeapAlloc)/(1<<20)*10) / 10
	goroutines := runtime.NumGoroutine()
	conns := botConns.Load()

	rateStr := "100.00% (初始)"
	statusEmoji := "🟢 稳定运行 (STABLE)"
	if stats.CreatedTotal > 0 {
		rate := float64(stats.VerifiedTotal) / float64(stats.CreatedTotal) * 100
		if rate > 100 {
			rate = 100
		}
		rateStr = fmt.Sprintf("%.2f%%", rate)
		if rate < 60 && stats.CreatedTotal > 5 {
			statusEmoji = "🟡 出现波动 (WARNING)"
		}
	}

	return fmt.Sprintf(`✦ OneAuth 运行监控简报 ✦
───────────────────────
⏱️ 运行时间：%s
🏷️ 系统版本：OneAuth %s (%s/%s)
⚡ 服务状态：%s

📊 鉴权统计：
  • 授权请求总数：%d 次
  • 验证码核销量：%d 次
  • 实时待核销数：%d 个
  • 鉴权核销成功率：%s

🤖 节点通信：
  • 反向 WS 状态：在线 (%d 个节点)
  • 协议内核：OneBot v11 / v12

💻 系统健康：
  • 运行时协程：%d
  • 内存占用：%.1f MB
  • 数据存储：SQLite WAL
───────────────────────
OneAuth QQ-OIDC 统一身份核验`,
		uptimeStr,
		verInfo.Version,
		verInfo.OS,
		verInfo.Arch,
		statusEmoji,
		stats.CreatedTotal,
		stats.VerifiedTotal,
		stats.Pending,
		rateStr,
		conns,
		goroutines,
		heapMB,
	)
}

// 连接状态原子量：供管理后台概览轮询 OneBot 反向 WS 的实时接入情况，
// 读写都不需要加锁（事件处理在独立 goroutine，连接生命周期在 handler）。
var (
	botConns          atomic.Int32
	botLastConnect    atomic.Int64 // unix 秒
	botLastDisconnect atomic.Int64 // unix 秒
	botLastEvent      atomic.Int64 // unix 秒
)

// Status 返回 OneBot 反向 WS 的实时连接概况。时间字段为 RFC3339，未发生过
// 时返回空字符串。
func Status() map[string]any {
	conns := botConns.Load()
	return map[string]any{
		"connected":       conns > 0,
		"connections":     conns,
		"last_connected":  unixRFC3339(botLastConnect.Load()),
		"last_disconnect": unixRFC3339(botLastDisconnect.Load()),
		"last_event":      unixRFC3339(botLastEvent.Load()),
	}
}

func unixRFC3339(sec int64) string {
	if sec == 0 {
		return ""
	}
	return time.Unix(sec, 0).UTC().Format(time.RFC3339)
}

func HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	token := database.GetSetting("onebot_token", "")
	if token != "" {
		auth := r.Header.Get("Authorization")
		queryToken := r.URL.Query().Get("access_token")
		valid := auth == "Bearer "+token || queryToken == token
		if !valid {
			log.Printf("[OneBot] 401 Unauthorized WS attempt from %s", r.RemoteAddr)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("WebSocket upgrade error:", err)
		return
	}
	defer conn.Close()
	conn.SetReadLimit(wsReadLimit)

	now := time.Now().Unix()
	botConns.Add(1)
	botLastConnect.Store(now)
	client := newWSClient(conn)
	registerClient(client)
	defer func() {
		unregisterClient(client)
		botConns.Add(-1)
		botLastDisconnect.Store(time.Now().Unix())
	}()

	log.Println("OneBot WebSocket connected:", r.RemoteAddr)

	events := make(chan []byte, eventQueueLen)
	workerDone := make(chan struct{})
	go func() {
		defer close(workerDone)
		// 单消费者按序处理：群消息事件之间保持到达顺序，
		// 同时把"每事件一个 goroutine"的无界并发改为固定 1 + 缓冲队列。
		for msg := range events {
			processEvent(msg, client)
		}
	}()

	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			log.Println("OneBot WebSocket disconnected:", r.RemoteAddr, err)
			close(events)
			<-workerDone
			return
		}
		select {
		case events <- message:
		default:
			log.Println("[OneBot] 事件队列已满，丢弃本条事件（等待机器人侧重发）")
		}
	}
}

func processEvent(raw []byte, optionalSender ...Sender) {
	var sender Sender
	if len(optionalSender) > 0 && optionalSender[0] != nil {
		sender = optionalSender[0]
	} else {
		sender = getActiveSender()
	}

	botLastEvent.Store(time.Now().Unix())

	var event map[string]interface{}
	if err := json.Unmarshal(raw, &event); err != nil {
		return
	}

	// Skip meta_event (v11) and meta (v12) heartbeats
	if postType, ok := event["post_type"].(string); ok && postType == "meta_event" {
		return
	}
	if typeVal, ok := event["type"].(string); ok && typeVal == "meta" {
		return
	}

	// NapCat reports messages sent by the bot's own account (how a group
	// admin relays a code) as post_type "message_sent" rather than "message";
	// they are group messages all the same and must reach the matcher below.
	selfSent := false
	if postType, ok := event["post_type"].(string); ok && postType == "message_sent" {
		selfSent = true
		event["post_type"] = "message"
	}

	// 应用级群绑定后不再按全局群号过滤消息：任意群的消息都可能携带某个
	// 会话的验证码，来源群是否匹配由 VerifyCode 对照会话绑定的群判断。

	var groupID string
	var userID string
	var text string

	// Detect v11
	if postType, ok := event["post_type"].(string); ok && postType == "message" {
		if msgType, ok := event["message_type"].(string); ok && msgType == "group" {
			if gID, ok := event["group_id"].(float64); ok {
				groupID = strconv.FormatInt(int64(gID), 10)
			}
			if uID, ok := event["user_id"].(float64); ok {
				userID = strconv.FormatInt(int64(uID), 10)
			}
			text = extractTextV11(event)
		}
	}

	// Detect v12
	if typeVal, ok := event["type"].(string); ok && typeVal == "message" {
		if detailType, ok := event["detail_type"].(string); ok && detailType == "group" {
			if c, ok := sender.(*wsClient); ok {
				c.isV12.Store(true)
			}
			if gID, ok := event["group_id"].(string); ok {
				groupID = gID
			}
			if uID, ok := event["user_id"].(string); ok {
				userID = uID
			}
			text = extractTextV12(event)
		}
	}

	// 心跳回显、私聊、notice/request 事件：与验证码无关，
	// 静默忽略，不再打 "Ignored message" 刷屏。
	if groupID == "" || userID == "" {
		return
	}

	text = strings.ToUpper(strings.TrimSpace(text))
	origin := "member"
	if selfSent {
		origin = "self/admin"
	}
	log.Printf("[OneBot] Received group message: '%s' from user: '%s' group: '%s' (%s)", loggable(text), userID, groupID, origin)

	// 指令匹配：#oidc 运行监控报告
	if text == "#OIDC" || strings.HasPrefix(text, "#OIDC ") {
		if database.GetSetting("bot_status_cmd_enabled", "true") != "false" {
			if checkGroupCooldown(groupID, 5*time.Second) {
				report := BuildStatusReport()
				if sender != nil {
					if err := sender.SendGroupMsg(groupID, report); err != nil {
						log.Printf("[OneBot] 回复群 %s #oidc 监控状态失败: %v", groupID, err)
					} else {
						log.Printf("[OneBot] ✓ 成功响应群 %s 的 #oidc 监控指令", groupID)
					}
				}
			} else {
				log.Printf("[OneBot] 群 %s 触发 #oidc 过于频繁，已冷却抑制", groupID)
			}
		}
		return
	}

	if codeRegex.MatchString(text) {
		sess, ok := session.DefaultManager.VerifyCode(identity.ProviderQQ, text, userID, groupID)
		if ok {
			log.Printf("[OneBot] ✓ 验证码 %s 已核销 → %s: %s | Session: %s\n", text, identity.Label(identity.ProviderQQ), userID, sess.SessionID)
		} else {
			log.Printf("[OneBot] ✗ 验证码匹配未成功: code='%s' not found or expired or group mismatch", text)
		}
		return
	}

	// Not a bare code: look for one inside the sentence. Longest match first
	// so a message that quotes two codes consumes the last one actually sent.
	if match := codeSearchRegex.FindAllString(text, -1); len(match) > 0 {
		candidate := match[len(match)-1]
		if sess, ok := session.DefaultManager.VerifyCode(identity.ProviderQQ, candidate, userID, groupID); ok {
			log.Printf("[OneBot] ✓ 验证码 %s 已核销 → %s: %s | Session: %s\n", candidate, identity.Label(identity.ProviderQQ), userID, sess.SessionID)
			return
		}
		// 提取出的候选未命中：多为普通聊天或长报文里的大写串（UUID、单号等），
		// 属正常流量，静默返回，不再打 "未命中正则" 日志。
	}
}

// loggable 把日志里的消息压成单行并截断，避免长报文（如机器人转发的错误报告）
// 打满日志。
func loggable(text string) string {
	oneLine := strings.ReplaceAll(strings.ReplaceAll(text, "\r", " "), "\n", " ")
	runes := []rune(oneLine)
	if len(runes) > 100 {
		return string(runes[:100]) + "…"
	}
	return oneLine
}

func extractTextV11(event map[string]interface{}) string {
	if rawMessage, ok := event["raw_message"].(string); ok && rawMessage != "" {
		return strings.TrimSpace(cqRegex.ReplaceAllString(rawMessage, ""))
	}
	return extractFromMessageArray(event)
}

func extractTextV12(event map[string]interface{}) string {
	if altMessage, ok := event["alt_message"].(string); ok && altMessage != "" {
		return strings.TrimSpace(altMessage)
	}
	return extractFromMessageArray(event)
}

func extractFromMessageArray(event map[string]interface{}) string {
	msgArray, ok := event["message"].([]interface{})
	if !ok {
		return ""
	}

	var texts []string
	for _, segIntf := range msgArray {
		if seg, ok := segIntf.(map[string]interface{}); ok {
			if typeVal, ok := seg["type"].(string); ok && typeVal == "text" {
				if data, ok := seg["data"].(map[string]interface{}); ok {
					if txt, ok := data["text"].(string); ok {
						texts = append(texts, txt)
					}
				}
			}
		}
	}
	return strings.TrimSpace(strings.Join(texts, ""))
}
