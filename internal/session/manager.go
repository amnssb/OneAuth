package session

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"
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
	QQNumber      string
	AuthCode      string
	Status        SessionStatus
	ExpiresAt     time.Time
	NotifyChan    chan struct{}
}

// 并发约定：session 发布到 map 之后，
//   - SessionID/ClientID/RedirectURI/State/CodeChallenge/VerifyCode/ExpiresAt/
//     NotifyChan 不可变，处理器（如 SSE）可无锁读取或等待 NotifyChan；
//   - QQNumber/Status/AuthCode 仅在 Manager.mu 写锁下读写，
//     处理器不得直接访问（统一走 Manager 的方法）。

type Manager struct {
	mu            sync.RWMutex
	sessions      map[string]*AuthSession
	codeIndex     map[string]*AuthSession
	authCodeIndex map[string]*AuthSession
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

func (m *Manager) CreateSession(clientID, redirectURI, state, challenge string, ttlSeconds int) (*AuthSession, error) {
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
			Status:        StatusPending,
			ExpiresAt:     time.Now().Add(time.Duration(ttlSeconds) * time.Second),
			NotifyChan:    make(chan struct{}),
		}

		m.sessions[sessionID] = session
		m.codeIndex[code] = session

		return session, nil
	}
	return nil, errors.New("failed to generate unique code after 100 attempts")
}

func (m *Manager) VerifyCode(code, qqNumber string) (*AuthSession, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, exists := m.codeIndex[code]
	if !exists {
		return nil, false
	}

	if time.Now().After(session.ExpiresAt) || session.Status != StatusPending {
		return nil, false
	}

	session.QQNumber = qqNumber
	session.Status = StatusVerified

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
