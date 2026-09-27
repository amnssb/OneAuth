package session

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"math/big"
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

func generateRandomHex(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// generateUniqueCode generates a unique verification code.
// MUST be called with m.mu held (write lock).
func (m *Manager) generateUniqueCode(length int) (string, error) {
	for i := 0; i < 100; i++ {
		code := make([]byte, length)
		for j := 0; j < length; j++ {
			idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
			if err != nil {
				return "", err
			}
			code[j] = charset[idx.Int64()]
		}
		strCode := string(code)

		if _, exists := m.codeIndex[strCode]; !exists {
			return strCode, nil
		}
	}
	return "", errors.New("failed to generate unique code after 100 attempts")
}

func (m *Manager) CreateSession(clientID, redirectURI, state, challenge string, ttlSeconds int) (*AuthSession, error) {
	sessionID, err := generateRandomHex(16)
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	code, err := m.generateUniqueCode(6)
	if err != nil {
		return nil, err
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
