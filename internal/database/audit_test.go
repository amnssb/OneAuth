package database

import (
	"path/filepath"
	"testing"
)

func TestAuditLogCRUD(t *testing.T) {
	db, err := InitDB(filepath.Join(t.TempDir(), "test_audit.db"))
	if err != nil {
		t.Fatalf("InitDB failed: %v", err)
	}
	defer func() {
		db.Close()
		WriteDB.Close()
	}()

	// 1. 插入审计日志
	err = RecordAuditLog("sess_123", "oa_test_client", "10001", "1.1.1.1", "Mozilla/5.0", "Windows", "Chrome", "desktop")
	if err != nil {
		t.Fatalf("RecordAuditLog failed: %v", err)
	}
	err = RecordAuditLog("sess_456", "oa_test_client", "20002", "2.2.2.2", "Mozilla/5.0 (iPhone)", "iOS", "Safari", "mobile")
	if err != nil {
		t.Fatalf("RecordAuditLog 2 failed: %v", err)
	}

	// 2. 查询全部
	logs, total, err := ListAuditLogs("", "", 10, 0)
	if err != nil {
		t.Fatalf("ListAuditLogs failed: %v", err)
	}
	if total != 2 || len(logs) != 2 {
		t.Fatalf("expected 2 logs, got %d (total: %d)", len(logs), total)
	}

	// 3. 按 QQ 过滤
	logsQQ, totalQQ, err := ListAuditLogs("10001", "", 10, 0)
	if err != nil {
		t.Fatalf("ListAuditLogs by QQ failed: %v", err)
	}
	if totalQQ != 1 || len(logsQQ) != 1 || logsQQ[0].QQNumber != "10001" {
		t.Fatalf("expected 1 log for QQ 10001, got %+v", logsQQ)
	}

	// 4. 按 IP 过滤
	logsIP, totalIP, err := ListAuditLogs("", "2.2.2.2", 10, 0)
	if err != nil {
		t.Fatalf("ListAuditLogs by IP failed: %v", err)
	}
	if totalIP != 1 || len(logsIP) != 1 || logsIP[0].ClientIP != "2.2.2.2" {
		t.Fatalf("expected 1 log for IP 2.2.2.2, got %+v", logsIP)
	}
}
