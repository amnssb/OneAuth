package session

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"oneauth/internal/database"
)

type SessionStatus string

const (
	StatusPending  SessionStatus = "PENDING"
	StatusVerified SessionStatus = "VERIFIED"
	StatusConsumed SessionStatus = "CONSUMED"
)

type AuthSession struct {
	SessionID     string
	ClientID      string
	RedirectURI   string
	State         string
	CodeChallenge string
	VerifyCode    string
	// GroupID 是该会话绑定的核验 QQ 群号。由发起授权的应用决定
	// （应用级 target_group_id），为空时回落到全局设置。核销时
	// 必须与消息来源群号一致，否则拒绝核销。
	GroupID       string
	// 核销后的平台身份：Provider 标识来源平台（见 internal/identity），
	// UserID 为该平台内的用户标识（qq 平台下即 QQ 号）。
	// 核销前两者均为空。
	Provider   string
	UserID     string
	AuthCode   string
	Status     SessionStatus
	ExpiresAt  time.Time
	NotifyChan chan struct{}
}

// 并发约定：session 发布到 map 之后，
//   - SessionID/ClientID/RedirectURI/State/CodeChallenge/VerifyCode/ExpiresAt/
//     NotifyChan 不可变，处理器（如 SSE）可无锁读取或等待 NotifyChan；
//   - Provider/UserID/Status/AuthCode 仅在 Manager.mu 写锁下读写，
//     处理器不得直接访问（统一走 Manager 的方法）。

type Manager struct {
	mu            sync.RWMutex
	sessions      map[string]*AuthSession
	codeIndex     map[string]*AuthSession
	authCodeIndex map[string]*AuthSession

	// 自进程启动以来的累计计数：创建过的会话总数与核销成功次数。
	// 与 sessions 的实时快照不同，它们只增不减（重启归零），供管理后台
	// 展示登录活跃度 —— 低流量部署下快照几乎恒为 0，累计值才有参考意义。
	totalCreated  atomic.Uint64
	totalVerified atomic.Uint64
}

var DefaultManager = NewManager()

func NewManager() *Manager {
	m := &Manager{
		sessions:      make(map[string]*AuthSession),
		codeIndex:     make(map[string]*AuthSession),
		authCodeIndex: make(map[string]*AuthSession),
	}
	go m.startCleaner()
	return m
}

const charset = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"

const (
	charsetLen    = 31        // len(charset)
	maxAcceptByte = byte(248) // 256 - 256%31：拒绝采样上限，保证到字符集的映射均匀
)

func generateRandomHex(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// randomCode 一次 rand.Read 取足随机字节并映射到字符集（拒绝采样消除模偏差），
// 替代原先每个字符一次 rand.Int + big.Int 分配的写法。
func randomCode(length int) (string, error) {
	out := make([]byte, 0, length)
	for len(out) < length {
		buf := make([]byte, length)
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		for _, b := range buf {
			if b < maxAcceptByte {
				out = append(out, charset[b%charsetLen])
				if len(out) == length {
					break
				}
			}
		}
	}
	return string(out), nil
}

func (m *Manager) CreateSession(clientID, redirectURI, state, challenge, groupID string, ttlSeconds int) (*AuthSession, error) {
	sessionID, err := generateRandomHex(16)
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for i := 0; i < 100; i++ {
		code, err := randomCode(6)
		if err != nil {
			return nil, err
		}
		if _, exists := m.codeIndex[code]; exists {
			continue
		}

		session := &AuthSession{
			SessionID:     sessionID,
			ClientID:      clientID,
			RedirectURI:   redirectURI,
			State:         state,
			CodeChallenge: challenge,
			VerifyCode:    code,
			GroupID:       groupID,
			Status:        StatusPending,
			ExpiresAt:     time.Now().Add(time.Duration(ttlSeconds) * time.Second),
			NotifyChan:    make(chan struct{}),
		}

		m.sessions[sessionID] = session
		m.codeIndex[code] = session
		m.totalCreated.Add(1)

		return session, nil
	}
	return nil, errors.New("failed to generate unique code after 100 attempts")
}

// VerifyCode 把验证码核销为平台身份并绑定到会话。provider 标识核销通道
// 来源（当前仅 identity.ProviderQQ，新平台接入各自通道时传自己的标识）。
// groupID 为消息来源群号，必须与会话绑定的 GroupID 一致才允许核销。
func (m *Manager) VerifyCode(provider, code, userID, groupID string) (*AuthSession, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, exists := m.codeIndex[code]
	if !exists {
		return nil, false
	}

	if time.Now().After(session.ExpiresAt) || session.Status != StatusPending {
		return nil, false
	}

	// 群号必须与会话绑定的群一致：应用级群绑定后，不同应用的验证码
	// 只能在各自绑定的群内核销，防止跨群冒用。
	if session.GroupID == "" || groupID != session.GroupID {
		return nil, false
	}

	session.Provider = provider
	session.UserID = userID
	session.Status = StatusVerified
	m.totalVerified.Add(1)

	delete(m.codeIndex, code)
	close(session.NotifyChan)

	return session, true
}

func (m *Manager) IssueAuthCode(sessionID string) (string, *AuthSession, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, exists := m.sessions[sessionID]
	if !exists {
		return "", nil, false
	}

	if session.Status != StatusVerified {
		return "", nil, false
	}

	authCode, err := generateRandomHex(24)
	if err != nil {
		return "", nil, false
	}

	session.AuthCode = authCode
	session.Status = StatusConsumed
	m.authCodeIndex[authCode] = session

	return authCode, session, true
}

func (m *Manager) ExchangeCode(authCode string) (*AuthSession, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, exists := m.authCodeIndex[authCode]
	if !exists {
		return nil, false
	}

	delete(m.authCodeIndex, authCode)
	return session, true
}

func (m *Manager) GetSession(sessionID string) (*AuthSession, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	session, exists := m.sessions[sessionID]
	return session, exists
}

// SessionStats 是内存会话按状态分布的快照，供管理后台概览轮询展示。
// CreatedTotal / VerifiedTotal 是自进程启动以来的累计值（只增不减，重启
// 归零），与上面的实时快照互补：前者回答"发生了多少登录"，后者回答
// "此刻有多少人在登录途中"。
type SessionStats struct {
	Pending  int
	Verified int
	Consumed int
	Total    int

	CreatedTotal  uint64
	VerifiedTotal uint64
}

func (m *Manager) Stats() SessionStats {
	var s SessionStats
	s.CreatedTotal = m.totalCreated.Load()
	s.VerifiedTotal = m.totalVerified.Load()

	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, sess := range m.sessions {
		switch sess.Status {
		case StatusPending:
			s.Pending++
		case StatusVerified:
			s.Verified++
		case StatusConsumed:
			s.Consumed++
		}
		s.Total++
	}
	return s
}

func (m *Manager) startCleaner() {
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		m.mu.Lock()
		now := time.Now()
		for id, session := range m.sessions {
			if now.After(session.ExpiresAt) {
				delete(m.sessions, id)
				if session.VerifyCode != "" {
					delete(m.codeIndex, session.VerifyCode)
				}
				if session.AuthCode != "" {
					delete(m.authCodeIndex, session.AuthCode)
				}
			}
		}
		m.mu.Unlock()
	}
}

// SaveStateToDB 将内存中当前活跃且未过期的会话快照持久化到数据库，
// 供版本更新或平滑热重启后恢复，实现业务会话零丢失（无感热更）。
func (m *Manager) SaveStateToDB() error {
	if database.WriteDB == nil {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	now := time.Now()
	tx, err := database.WriteDB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec("DELETE FROM transient_sessions_backup"); err != nil {
		return err
	}

	stmt, err := tx.Prepare(`
		INSERT INTO transient_sessions_backup 
		(session_id, client_id, redirect_uri, state, code_challenge, verify_code, group_id, provider, user_id, auth_code, status, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	count := 0
	for _, sess := range m.sessions {
		if now.Before(sess.ExpiresAt) {
			_, err := stmt.Exec(
				sess.SessionID, sess.ClientID, sess.RedirectURI, sess.State,
				sess.CodeChallenge, sess.VerifyCode, sess.GroupID,
				sess.Provider, sess.UserID, sess.AuthCode,
				string(sess.Status), sess.ExpiresAt,
			)
			if err != nil {
				log.Printf("[无感更新] 会话备份写入异常: %v", err)
				continue
			}
			count++
		}
	}

	if err := tx.Commit(); err != nil {
		return err
	}
	log.Printf("[无感更新] 已持久化 %d 条活跃会话用于平滑重启恢复", count)
	return nil
}

// RestoreStateFromDB 在系统启动时从数据库恢复未过期的瞬态会话，实现跨更新会话无感接力。
func (m *Manager) RestoreStateFromDB() (int, error) {
	if database.DB == nil {
		return 0, nil
	}
	rows, err := database.DB.Query(`
		SELECT session_id, client_id, redirect_uri, state, code_challenge, verify_code, 
		       group_id, provider, user_id, auth_code, status, expires_at
		FROM transient_sessions_backup
		WHERE expires_at > CURRENT_TIMESTAMP
	`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	m.mu.Lock()
	defer m.mu.Unlock()

	restored := 0
	for rows.Next() {
		var s AuthSession
		var statusStr string
		var expiresAt time.Time
		if err := rows.Scan(
			&s.SessionID, &s.ClientID, &s.RedirectURI, &s.State,
			&s.CodeChallenge, &s.VerifyCode, &s.GroupID,
			&s.Provider, &s.UserID, &s.AuthCode,
			&statusStr, &expiresAt,
		); err != nil {
			continue
		}

		s.Status = SessionStatus(statusStr)
		s.ExpiresAt = expiresAt
		s.NotifyChan = make(chan struct{})
		if s.Status == StatusVerified {
			close(s.NotifyChan)
		}

		m.sessions[s.SessionID] = &s
		if s.VerifyCode != "" && s.Status == StatusPending {
			m.codeIndex[s.VerifyCode] = &s
		}
		if s.AuthCode != "" && s.Status == StatusConsumed {
			m.authCodeIndex[s.AuthCode] = &s
		}
		restored++
	}

	if restored > 0 {
		log.Printf("[无感更新] 已从备份成功恢复 %d 条活跃会话状态", restored)
	}
	go func() {
		if database.WriteDB != nil {
			_, _ = database.WriteDB.Exec("DELETE FROM transient_sessions_backup WHERE expires_at <= CURRENT_TIMESTAMP")
		}
	}()
	return restored, nil
}
