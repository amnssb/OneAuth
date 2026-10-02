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

func TestHandleCheckUpdate(t *testing.T) {
	db, err := database.InitDB(filepath.Join(t.TempDir(), "update_check_test.db"))
	if err != nil {
		t.Fatalf("InitDB failed: %v", err)
	}
	defer db.Close()
	defer database.WriteDB.Close()

	// 1. 测试 404 场景（无正式 Release，如当前真实仓库环境）
	mock404Server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message":"Not Found"}`))
	}))
	defer mock404Server.Close()

	database.SetSetting("update_check_url", mock404Server.URL)

	req := httptest.NewRequest(http.MethodGet, "/api/admin/update/check", nil)
	w := httptest.NewRecorder()
	handleCheckUpdate(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200 for 404 release, got %d", w.Code)
	}

	var res404 map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &res404); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if res404["has_update"] != false {
		t.Errorf("expected has_update false, got %v", res404["has_update"])
	}
	if res404["message"] == nil || res404["message"] == "" {
		t.Errorf("expected friendly message for 404, got %v", res404["message"])
	}

	// 2. 测试 200 有新版本场景
	mock200Server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"tag_name": "v99.0.0",
			"name": "OneAuth v99.0.0",
			"body": "Awesome updates",
			"published_at": "2026-10-02T12:00:00Z",
			"html_url": "https://github.com/amnssb/OneAuth/releases/tag/v99.0.0"
		}`))
	}))
	defer mock200Server.Close()

	database.SetSetting("update_check_url", mock200Server.URL)
	w2 := httptest.NewRecorder()
	handleCheckUpdate(w2, req)

	var res200 map[string]any
	if err := json.Unmarshal(w2.Body.Bytes(), &res200); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if res200["has_update"] != true {
		t.Errorf("expected has_update true, got %v", res200["has_update"])
	}
	if res200["latest_version"] != "v99.0.0" {
		t.Errorf("expected latest_version v99.0.0, got %v", res200["latest_version"])
	}

	// 3. 测试 403 频率限制场景
	mock403Server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Ratelimit-Remaining", "0")
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"message":"API rate limit exceeded"}`))
	}))
	defer mock403Server.Close()

	database.SetSetting("update_check_url", mock403Server.URL)
	w3 := httptest.NewRecorder()
	handleCheckUpdate(w3, req)

	var res403 map[string]any
	if err := json.Unmarshal(w3.Body.Bytes(), &res403); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if res403["has_update"] != false {
		t.Errorf("expected has_update false, got %v", res403["has_update"])
	}
	if res403["error"] == nil || res403["error"] == "" {
		t.Errorf("expected rate limit error message, got %v", res403["error"])
	}
}

