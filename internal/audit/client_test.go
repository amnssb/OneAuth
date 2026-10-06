package audit

import (
	"net/http"
	"testing"
)

func TestExtractClientIP(t *testing.T) {
	req, _ := http.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.1:12345"

	// 1. 无 header 时取 RemoteAddr
	if ip := ExtractClientIP(req); ip != "192.168.1.1" {
		t.Fatalf("expected 192.168.1.1, got %s", ip)
	}

	// 2. CF-Connecting-IP 优先
	req.Header.Set("CF-Connecting-IP", "1.1.1.1")
	req.Header.Set("X-Forwarded-For", "2.2.2.2, 3.3.3.3")
	if ip := ExtractClientIP(req); ip != "1.1.1.1" {
		t.Fatalf("expected 1.1.1.1 from CF-Connecting-IP, got %s", ip)
	}

	// 3. XFF 逗号分隔首位有效 IP
	req.Header.Del("CF-Connecting-IP")
	if ip := ExtractClientIP(req); ip != "2.2.2.2" {
		t.Fatalf("expected 2.2.2.2 from XFF, got %s", ip)
	}
}

func TestExtractDeviceInfo(t *testing.T) {
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0")

	info := ExtractDeviceInfo(req)
	if info.OS != "Windows" || info.Browser != "Edge" || info.DeviceType != "desktop" {
		t.Fatalf("unexpected parsed device: %+v", info)
	}

	// 移动端 iPhone
	req.Header.Set("User-Agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1")
	info = ExtractDeviceInfo(req)
	if info.OS != "iOS" || info.Browser != "Safari" || info.DeviceType != "mobile" {
		t.Fatalf("unexpected parsed device: %+v", info)
	}
}
