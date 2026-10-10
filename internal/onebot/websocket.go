package onebot

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net"
	"net/http"
	"net/url"
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

// CheckOrigin 只放行同源或不带 Origin 的非浏览器客户端（NapCat、
// Go-cqhttp 这类反向 WS 发起方不会带 Origin）。原来无条件 return true
// 等于允许任意网页在访客浏览器里借用户的网络位置连上这条 WS。
var upgrader = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}}

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

	// 成员二次核验的动作回包路由：每个动作请求带独立 echo，回包按 echo
	// 分发回等待中的调用方，与事件通道互不干扰。
	pendingMu sync.Mutex
	pending   map[string]chan map[string]interface{}
	echoSeq   atomic.Uint64
}

func newWSClient(conn *websocket.Conn) *wsClient {
	return &wsClient{conn: conn, pending: make(map[string]chan map[string]interface{})}
}

// MemberChecker 供 processEvent 在核销验证码前反查“该 QQ 是否真在群里”，
// 不再单方面信任入站事件里的 user_id / group_id 字段。
type MemberChecker interface {
	CheckGroupMember(groupID, userID string) (bool, error)
}

var _ MemberChecker = (*wsClient)(nil)

// CheckGroupMember 向机器人发起 get_group_member_info 并等待回包（3s 超时）。
func (c *wsClient) CheckGroupMember(groupID, userID string) (bool, error) {
	gid, err := strconv.ParseInt(groupID, 10, 64)
	if err != nil {
		return false, fmt.Errorf("非法 group_id: %q", groupID)
	}
	uid, err := strconv.ParseInt(userID, 10, 64)
	if err != nil {
		return false, fmt.Errorf("非法 user_id: %q", userID)
	}

	echo := "chk_" + strconv.FormatUint(c.echoSeq.Add(1), 10)
	ch := make(chan map[string]interface{}, 1)
	c.pendingMu.Lock()
	c.pending[echo] = ch
	c.pendingMu.Unlock()
	defer func() {
		c.pendingMu.Lock()
		delete(c.pending, echo)
		c.pendingMu.Unlock()
	}()

	payload := map[string]interface{}{
		"action": "get_group_member_info",
		"params": map[string]interface{}{"group_id": gid, "user_id": uid, "no_cache": true},
		"echo":   echo,
	}
	c.writeMu.Lock()
	werr := c.conn.WriteJSON(payload)
	c.writeMu.Unlock()
	if werr != nil {
		return false, werr
	}

	select {
	case resp := <-ch:
		return memberInfoConfirms(resp), nil
	case <-time.After(3 * time.Second):
		return false, fmt.Errorf("get_group_member_info 超时")
	}
}

// memberInfoConfirms 解析 OneBot v11/v12 动作回包：只有明确成功且携带
// 成员数据时才视为“在群内”，任何错误/超时语义都按不确认处理。
func memberInfoConfirms(resp map[string]interface{}) bool {
	if status, ok := resp["status"].(string); ok && status != "ok" {
		return false
	}
	if rc, ok := resp["retcode"].(float64); ok && rc != 0 {
		return false
	}
	if ok, exists := resp["ok"].(bool); exists && !ok {
		return false
	}
	data, hasData := resp["data"]
	if !hasData || data == nil {
		return false
	}
	if m, isMap := data.(map[string]interface{}); isMap {
		if e, hasErr := m["error"]; hasErr && e != nil {
			if em, ok := e.(map[string]interface{}); ok && len(em) > 0 {
				return false
			}
		}
	}
	return true
}

// deliverPending 把带 echo 的动作回包分发给等待中的调用方；返回 true 表示
// 该报文是回包（不再当事件处理）。
func deliverPending(c *wsClient, raw []byte) bool {
	if !bytes.Contains(raw, []byte(`"echo"`)) {
		return false
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return false
	}
	var echo string
	switch v := resp["echo"].(type) {
	case string:
		echo = v
	case float64:
		echo = strconv.FormatInt(int64(v), 10)
	}
	if echo == "" {
		return false
	}
	c.pendingMu.Lock()
	ch, waiting := c.pending[echo]
	c.pendingMu.Unlock()
	if !waiting {
		return false
	}
	select {
	case ch <- resp:
	default:
	}
	return true
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

// wsToken 解析并强制 OneBot 反向 WS 口令：token 为空一律 503（fail-closed）。
// 历史上 `if token != ""` 意味着“没配口令 = 谁都能连”，配合随源码公开的
// 默认值等于认证形同虚设。
func wsToken() string {
	return strings.TrimSpace(database.GetSetting("onebot_token", ""))
}

// wsIPAllowed 应用 onebot_ws_ip_allowlist（逗号分隔 IP / CIDR）。未配置时
// 放行全部来源：网络层隔离交给部署方，配置后即在应用层二次收口。
func wsIPAllowed(r *http.Request) bool {
	raw := strings.TrimSpace(database.GetSetting("onebot_ws_ip_allowlist", ""))
	if raw == "" {
		return true
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(strings.TrimSpace(host))
	if ip == nil {
		return false
	}
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if strings.Contains(item, "/") {
			if _, cidr, err := net.ParseCIDR(item); err == nil && cidr.Contains(ip) {
				return true
			}
			continue
		}
		if allowed := net.ParseIP(item); allowed != nil && allowed.Equal(ip) {
			return true
		}
	}
	return false
}

func HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	token := wsToken()
	if token == "" {
		log.Printf("[OneBot] 503 拒绝 WS 连接 %s：onebot_token 未配置", r.RemoteAddr)
		http.Error(w, "OneBot WS disabled (token not configured)", http.StatusServiceUnavailable)
		return
	}
	auth := r.Header.Get("Authorization")
	queryToken := r.URL.Query().Get("access_token")
	expectedAuth := "Bearer " + token
	validAuth := subtle.ConstantTimeCompare([]byte(auth), []byte(expectedAuth)) == 1
	validQuery := subtle.ConstantTimeCompare([]byte(queryToken), []byte(token)) == 1
	if !validAuth && !validQuery {
		log.Printf("[OneBot] 401 Unauthorized WS attempt from %s", r.RemoteAddr)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if !wsIPAllowed(r) {
		log.Printf("[OneBot] 403 来源 IP 不在 onebot_ws_ip_allowlist 白名单内: %s", r.RemoteAddr)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
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
		if deliverPending(client, message) {
			continue
		}
		select {
		case events <- message:
		default:
			log.Println("[OneBot] 事件队列已满，丢弃本条事件（等待机器人侧重发）")
		}
	}
}

// numericID 把事件里的 QQ 号 / 群号收敛成纯数字字符串。v12 上游给的是
// 原始字符串，若原样透传，"<img src=x onerror=...>" 这类注入会一路流进
// 会话身份、审计日志与后台 DOM（存储型 XSS），这里统一拒收非数字。
func numericID(v interface{}) (string, bool) {
	switch t := v.(type) {
	case float64:
		if math.IsNaN(t) || math.IsInf(t, 0) || t < 0 || t != math.Trunc(t) || t > math.MaxInt64 {
			return "", false
		}
		return strconv.FormatInt(int64(t), 10), true
	case int64:
		if t < 0 {
			return "", false
		}
		return strconv.FormatInt(t, 10), true
	case int:
		if t < 0 {
			return "", false
		}
		return strconv.Itoa(t), true
	case string:
		s := strings.TrimSpace(t)
		if s == "" || len(s) > 20 {
			return "", false
		}
		if _, err := strconv.ParseUint(s, 10, 64); err != nil {
			return "", false
		}
		return s, true
	}
	return "", false
}

// 验证码尝试限流：同一群 60 次/分钟、同一 QQ 30 次/分钟，防脚本爆破
// 六位验证码与刷核销接口。
const (
	verifyWindow    = time.Minute
	verifyMaxGroup  = 60
	verifyMaxUser   = 30
	verifyLimitKeys = 8192
)

var (
	verifyLimitMu  sync.Mutex
	verifyAttempts = make(map[string][]time.Time)
)

func attemptAllowed(key string, max int, now time.Time) bool {
	stamps := verifyAttempts[key]
	fresh := stamps[:0]
	for _, t := range stamps {
		if now.Sub(t) < verifyWindow {
			fresh = append(fresh, t)
		}
	}
	if len(fresh) >= max {
		verifyAttempts[key] = fresh
		return false
	}
	verifyAttempts[key] = append(fresh, now)
	return true
}

func allowVerifyAttempt(groupID, userID string) bool {
	now := time.Now()
	verifyLimitMu.Lock()
	defer verifyLimitMu.Unlock()
	if len(verifyAttempts) > verifyLimitKeys {
		for k, stamps := range verifyAttempts {
			if len(stamps) == 0 || now.Sub(stamps[len(stamps)-1]) >= verifyWindow {
				delete(verifyAttempts, k)
			}
		}
	}
	return attemptAllowed("g:"+groupID, verifyMaxGroup, now) &&
		attemptAllowed("u:"+userID, verifyMaxUser, now)
}

// admissionCheck 是核销前的统一闸门：先过尝试限流，再按配置做群成员身份
// 二次核验（拿事件里的 group_id/user_id 反查机器人，不信任入站字段）。
func admissionCheck(sender Sender, groupID, userID, code string) bool {
	if !allowVerifyAttempt(groupID, userID) {
		log.Printf("[OneBot] ⚠ 群 %s / QQ %s 验证码尝试超频，已拒绝 (code=%s)", groupID, userID, code)
		return false
	}
	if database.GetSetting("onebot_verify_member", "false") != "true" {
		return true
	}
	mc, ok := sender.(MemberChecker)
	if !ok {
		log.Printf("[OneBot] ⚠ 已开启群成员二次核验，但当前连接不支持成员查询，拒绝核销 (group=%s user=%s)", groupID, userID)
		return false
	}
	inGroup, err := mc.CheckGroupMember(groupID, userID)
	if err != nil {
		log.Printf("[OneBot] ⚠ 群成员二次核验失败，拒绝核销 (group=%s user=%s): %v", groupID, userID, err)
		return false
	}
	if !inGroup {
		log.Printf("[OneBot] ⚠ 事件声称的 QQ %s 经反查不在群 %s 内，拒绝核销", userID, groupID)
		return false
	}
	return true
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
			groupID, _ = numericID(event["group_id"])
			userID, _ = numericID(event["user_id"])
			text = extractTextV11(event)
		}
	}

	// Detect v12
	if typeVal, ok := event["type"].(string); ok && typeVal == "message" {
		if detailType, ok := event["detail_type"].(string); ok && detailType == "group" {
			if c, ok := sender.(*wsClient); ok {
				c.isV12.Store(true)
			}
			groupID, _ = numericID(event["group_id"])
			userID, _ = numericID(event["user_id"])
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
		if !admissionCheck(sender, groupID, userID, text) {
			return
		}
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
		if !admissionCheck(sender, groupID, userID, candidate) {
			return
		}
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
