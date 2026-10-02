package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"oneauth/internal/database"
	"oneauth/internal/version"
)

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		v1, v2 string
		want   int
	}{
		{"v1.1.0", "v1.1.0", 0},
		{"v1.2.0", "v1.1.0", 1},
		{"v1.0.0", "v1.1.0", -1},
		{"1.2.1", "1.2.0", 1},
		{"v2.0.0-rc1", "v1.9.9", 1},
		{"v1.1.0", "v1.1.0-beta", 0},
	}

	for _, tt := range tests {
		got := compareVersions(tt.v1, tt.v2)
		if got != tt.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d", tt.v1, tt.v2, got, tt.want)
		}
	}
}

func TestHandleVersionPublic(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/version", nil)
	w := httptest.NewRecorder()

	HandleVersion(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	var info version.Info
	if err := json.Unmarshal(w.Body.Bytes(), &info); err != nil {
		t.Fatalf("failed to decode version info: %v", err)
	}
	if info.Version == "" {
		t.Fatal("expected non-empty version")
	}
}

func TestSaveAndRestoreAdminSessions(t *testing.T) {
	db, err := database.InitDB(filepath.Join(t.TempDir(), "admin_session_test.db"))
	if err != nil {
		t.Fatalf("InitDB failed: %v", err)
	}
	defer db.Close()
	defer database.WriteDB.Close()

	token := "test_admin_token_123"
	adminStore.put(token, &adminClaims{
		Username: "admin_tester",
		IssuedAt: time.Now().Unix(),
		Exp:      time.Now().Add(time.Hour).Unix(),
	})

	if err := SaveAdminSessions(); err != nil {
		t.Fatalf("SaveAdminSessions failed: %v", err)
	}

	// 清空内存 map
	adminStore.mu.Lock()
	adminStore.sessions = make(map[string]*adminClaims)
	adminStore.mu.Unlock()

	if _, ok := adminStore.get(token); ok {
		t.Fatal("expected token to be cleared from memory")
	}

	// 模拟重启恢复
	count, err := RestoreAdminSessions()
	if err != nil {
		t.Fatalf("RestoreAdminSessions failed: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 restored admin session, got %d", count)
	}

	claim, ok := adminStore.get(token)
	if !ok {
		t.Fatal("expected token to be restored")
	}
	if claim.Username != "admin_tester" {
		t.Fatalf("expected username admin_tester, got %s", claim.Username)
	}
}
