package onebot

import (
	"encoding/json"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"oneauth/internal/database"
	"oneauth/internal/session"

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

	log.Println("OneBot WebSocket connected:", r.RemoteAddr)

	events := make(chan []byte, eventQueueLen)
	workerDone := make(chan struct{})
	go func() {
		defer close(workerDone)
		// 单消费者按序处理：群消息事件之间保持到达顺序，
		// 同时把"每事件一个 goroutine"的无界并发改为固定 1 + 缓冲队列。
		for msg := range events {
			processEvent(msg)
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

func processEvent(raw []byte) {
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

	targetGroupID := database.GetSetting("target_group_id", "")
	if targetGroupID == "" {
		return
	}

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
			if gID, ok := event["group_id"].(string); ok {
				groupID = gID
			}
			if uID, ok := event["user_id"].(string); ok {
				userID = uID
			}
			text = extractTextV12(event)
		}
	}

	// 心跳回显、私聊、notice/request 事件、非目标群消息：与验证码无关，
	// 静默忽略，不再打 "Ignored message" 刷屏。
	if groupID == "" || userID == "" || groupID != targetGroupID {
		return
	}

	text = strings.ToUpper(strings.TrimSpace(text))
	origin := "member"
	if selfSent {
		origin = "self/admin"
	}
	log.Printf("[OneBot] Received target group message: '%s' from user: '%s' (%s)", loggable(text), userID, origin)

	if codeRegex.MatchString(text) {
		sess, ok := session.DefaultManager.VerifyCode(text, userID)
		if ok {
			log.Printf("[OneBot] ✓ 验证码 %s 已核销 → QQ: %s | Session: %s\n", text, userID, sess.SessionID)
		} else {
			log.Printf("[OneBot] ✗ 验证码匹配未成功: code='%s' not found or expired", text)
		}
		return
	}

	// Not a bare code: look for one inside the sentence. Longest match first
	// so a message that quotes two codes consumes the last one actually sent.
	if match := codeSearchRegex.FindAllString(text, -1); len(match) > 0 {
		candidate := match[len(match)-1]
		if sess, ok := session.DefaultManager.VerifyCode(candidate, userID); ok {
			log.Printf("[OneBot] ✓ 验证码 %s 已核销 → QQ: %s | Session: %s\n", candidate, userID, sess.SessionID)
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
