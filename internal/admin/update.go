package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"oneauth/internal/database"
	"oneauth/internal/session"
	"oneauth/internal/version"
)

// ShutdownServer 供主服务注入 HTTP Server 关闭方法，以供无感平滑重启时释放端口
var ShutdownServer func(context.Context) error

// HandleVersion 公共端点：GET /api/version
func HandleVersion(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, version.Get())
}

// handleAdminVersion 管理后台详细版本端点：GET /api/admin/version
func handleAdminVersion(w http.ResponseWriter, r *http.Request) {
	info := version.Get()
	resp := map[string]any{
		"version":    info,
		"uptime_sec": int64(time.Since(processStart).Seconds()),
		"started_at": processStart.Format(time.RFC3339),
	}
	writeJSON(w, http.StatusOK, resp)
}

// GitHubRelease 代表 GitHub Releases 接口返回的元数据结构
type GitHubRelease struct {
	TagName     string `json:"tag_name"`
	Name        string `json:"name"`
	Body        string `json:"body"`
	PublishedAt string `json:"published_at"`
	HTMLURL     string `json:"html_url"`
	Assets      []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
		Size               int64  `json:"size"`
	} `json:"assets"`
}

// compareVersions 比较两个形如 v1.2.3 或 1.2.3 的版本号。
// 返回 1 (v1 > v2), -1 (v1 < v2), 0 (v1 == v2)
func compareVersions(v1, v2 string) int {
	v1 = strings.TrimPrefix(strings.TrimSpace(v1), "v")
	v2 = strings.TrimPrefix(strings.TrimSpace(v2), "v")

	parts1 := strings.Split(v1, ".")
	parts2 := strings.Split(v2, ".")

	maxLen := len(parts1)
	if len(parts2) > maxLen {
		maxLen = len(parts2)
	}

	for i := 0; i < maxLen; i++ {
		var n1, n2 int
		if i < len(parts1) {
			// 过滤 prerelease 后缀如 -beta, -rc
			p := strings.Split(parts1[i], "-")[0]
			n1, _ = strconv.Atoi(p)
		}
		if i < len(parts2) {
			p := strings.Split(parts2[i], "-")[0]
			n2, _ = strconv.Atoi(p)
		}
		if n1 > n2 {
			return 1
		}
		if n1 < n2 {
			return -1
		}
	}
	return 0
}

// handleCheckUpdate 检查新版本：GET /api/admin/update/check
func handleCheckUpdate(w http.ResponseWriter, r *http.Request) {
	checkURL := strings.TrimSpace(database.GetSetting("update_check_url", "https://api.github.com/repos/amnssb/OneAuth/releases/latest"))
	if checkURL == "" {
		checkURL = "https://api.github.com/repos/amnssb/OneAuth/releases/latest"
	}

	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 12 * time.Second,
	}

	proxySetting := strings.TrimSpace(database.GetSetting("update_proxy", ""))
	if proxySetting != "" {
		if proxyURL, err := url.Parse(proxySetting); err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		} else {
			log.Printf("[检查更新] 解析配置代理地址失败 (%s): %v", proxySetting, err)
		}
	}

	client := &http.Client{
		Timeout:   15 * time.Second,
		Transport: transport,
	}

	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, checkURL, nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "创建检查请求失败: "+err.Error())
		return
	}
	req.Header.Set("User-Agent", "OneAuth-Server/"+version.Version)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := client.Do(req)
	if err != nil {
		errStr := err.Error()
		friendlyErr := "检查更新网络连接超时或离线"
		if strings.Contains(errStr, "deadline exceeded") || strings.Contains(errStr, "Client.Timeout") || strings.Contains(errStr, "timeout") {
			friendlyErr = "连接更新源超时（国内访问 GitHub 受限）。建议配置 HTTP/SOCKS5 代理或自定义镜像源"
		} else if strings.Contains(errStr, "connectex") || strings.Contains(errStr, "connection refused") || strings.Contains(errStr, "no route to host") {
			friendlyErr = "无法连通更新服务器（网络未连通或代理不可用）"
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"has_update":      false,
			"current_version": version.Version,
			"latest_version":  version.Version,
			"error":           friendlyErr + fmt.Sprintf(" (详情: %s)", errStr),
			"checked_at":      time.Now().Format(time.RFC3339),
		})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		// GitHub 仓库在未发 Release 之前，/releases/latest 会返回 404 Not Found
		writeJSON(w, http.StatusOK, map[string]any{
			"has_update":      false,
			"current_version": version.Version,
			"latest_version":  version.Version,
			"message":         "官方仓库暂未发布正式 Release 发行版，当前运行已是主干最新版本",
			"checked_at":      time.Now().Format(time.RFC3339),
		})
		return
	}

	if resp.StatusCode == http.StatusForbidden {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		errMsg := "GitHub API 请求被拒绝 (403)"
		if strings.Contains(string(bodyBytes), "rate limit") || resp.Header.Get("X-Ratelimit-Remaining") == "0" {
			errMsg = "GitHub API 匿名访问频次已超限 (60次/小时)，请稍后重试或配置代理"
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"has_update":      false,
			"current_version": version.Version,
			"latest_version":  version.Version,
			"error":           errMsg,
			"checked_at":      time.Now().Format(time.RFC3339),
		})
		return
	}

	if resp.StatusCode != http.StatusOK {
		writeJSON(w, http.StatusOK, map[string]any{
			"has_update":      false,
			"current_version": version.Version,
			"latest_version":  version.Version,
			"error":           fmt.Sprintf("远程接口响应状态码: %d", resp.StatusCode),
			"checked_at":      time.Now().Format(time.RFC3339),
		})
		return
	}

	var rel GitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		writeError(w, http.StatusInternalServerError, "解析版本数据失败: "+err.Error())
		return
	}

	latestVer := rel.TagName
	hasUpdate := compareVersions(latestVer, version.Version) > 0

	respMap := map[string]any{
		"has_update":      hasUpdate,
		"current_version": version.Version,
		"latest_version":  latestVer,
		"release_name":    rel.Name,
		"release_notes":   rel.Body,
		"release_url":     rel.HTMLURL,
		"published_at":    rel.PublishedAt,
		"checked_at":      time.Now().Format(time.RFC3339),
	}
	if !hasUpdate {
		respMap["message"] = fmt.Sprintf("当前已是最新发布版本 (%s)", latestVer)
	}

	writeJSON(w, http.StatusOK, respMap)
}

// handleSeamlessRestart 平滑热重启服务：POST /api/admin/update/restart
func handleSeamlessRestart(w http.ResponseWriter, r *http.Request) {
	log.Printf("[无感更新] 收到管理员 (IP: %s) 发起的平滑热重载请求", clientIP(r))

	// 1. 先回复客户端 HTTP 200，让前端感知到更新已触发
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "restarting",
		"message": "正在执行无感平滑热重载，瞬态会话已安全备份，服务将在 1 秒内平滑拉起...",
	})
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	// 2. 异步执行备份、释放端口、拉起新进程并退出旧进程
	go triggerSeamlessRestart()
}

func triggerSeamlessRestart() {
	time.Sleep(250 * time.Millisecond) // 缓冲让 HTTP 响应完全写出到 TCP 缓冲区

	log.Println("[无感更新] 正在保存瞬态业务会话与管理令牌到持久化存储...")
	if err := session.DefaultManager.SaveStateToDB(); err != nil {
		log.Printf("[无感更新] 会话备份失败: %v", err)
	}
	if err := SaveAdminSessions(); err != nil {
		log.Printf("[无感更新] 管理员会话备份失败: %v", err)
	}

	exePath, err := os.Executable()
	if err != nil {
		log.Printf("[无感更新] 获取可执行程序路径失败: %v", err)
		return
	}

	workDir, err := os.Getwd()
	if err != nil {
		workDir = filepath.Dir(exePath)
	}

	// 3. 优雅关闭旧 HTTP Server，释放端口监听
	if ShutdownServer != nil {
		log.Println("[无感更新] 正在关闭当前端口监听并注销连接...")
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = ShutdownServer(ctx)
		cancel()
	}

	// 4. 拉起新进程
	log.Printf("[无感更新] 正在启动新实例: %s ...", exePath)
	cmd := exec.Command(exePath, os.Args[1:]...)
	cmd.Dir = workDir
	cmd.Env = os.Environ()
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Start(); err != nil {
		log.Fatalf("[无感更新] 拉起新进程失败: %v", err)
		return
	}

	log.Printf("[无感更新] 新实例已成功拉起 (PID: %d)，旧实例安全退出", cmd.Process.Pid)
	os.Exit(0)
}

// handleApplyUpdate 在线热更新二进制：POST /api/admin/update/apply
func handleApplyUpdate(w http.ResponseWriter, r *http.Request) {
	log.Printf("[无感更新] 收到管理员 (IP: %s) 发起的二进制更新应用请求", clientIP(r))

	// 限制文件上传大小为 100MB
	r.Body = http.MaxBytesReader(w, r.Body, 100<<20)
	file, _, err := r.FormFile("binary")
	if err != nil {
		writeError(w, http.StatusBadRequest, "请上传有效的二进制文件: "+err.Error())
		return
	}
	defer file.Close()

	exePath, err := os.Executable()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "获取程序路径失败: "+err.Error())
		return
	}

	dir := filepath.Dir(exePath)
	tempFile, err := os.CreateTemp(dir, "oneauth-update-*.tmp")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "创建临时更新文件失败: "+err.Error())
		return
	}
	tempPath := tempFile.Name()

	if _, err := io.Copy(tempFile, file); err != nil {
		tempFile.Close()
		_ = os.Remove(tempPath)
		writeError(w, http.StatusInternalServerError, "写入临时更新文件失败: "+err.Error())
		return
	}
	tempFile.Close()

	// 赋予可执行权限
	_ = os.Chmod(tempPath, 0755)

	// 备份当前程序（Windows 支持把正在运行的文件重命名为 .old）
	oldPath := exePath + ".old"
	_ = os.Remove(oldPath) // 移除旧的 .old 备份
	if err := os.Rename(exePath, oldPath); err != nil {
		_ = os.Remove(tempPath)
		writeError(w, http.StatusInternalServerError, "重命名当前运行程序失败: "+err.Error())
		return
	}

	// 移动新程序到目标位置
	if err := os.Rename(tempPath, exePath); err != nil {
		// 回滚
		_ = os.Rename(oldPath, exePath)
		_ = os.Remove(tempPath)
		writeError(w, http.StatusInternalServerError, "替换新可执行文件失败: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"success": true,
		"message": "新版本二进制已成功就绪，正在无感平滑切换...",
	})
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	go triggerSeamlessRestart()
}
