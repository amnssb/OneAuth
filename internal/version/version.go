package version

import (
	"fmt"
	"runtime"
)

var (
	// Version 当前软件版本号，可由编译参数 -ldflags "-X oneauth/internal/version.Version=v1.1.0" 注入
	Version = "v1.1.0"
	// GitCommit Git 提交哈希，可由编译参数 -ldflags "-X oneauth/internal/version.GitCommit=..." 注入
	GitCommit = "dev"
	// BuildDate 构建时间，可由编译参数 -ldflags "-X oneauth/internal/version.BuildDate=..." 注入
	BuildDate = ""
)

// Info 包含完整的版本与运行时环境信息
type Info struct {
	Version   string `json:"version"`
	GitCommit string `json:"git_commit"`
	BuildDate string `json:"build_date,omitempty"`
	GoVersion string `json:"go_version"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	Compiler  string `json:"compiler"`
}

// Get 获取当前版本信息结构体
func Get() Info {
	return Info{
		Version:   Version,
		GitCommit: GitCommit,
		BuildDate: BuildDate,
		GoVersion: runtime.Version(),
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		Compiler:  runtime.Compiler,
	}
}

// Full 返回格式化后的完整版本描述字符串
func Full() string {
	dateStr := ""
	if BuildDate != "" {
		dateStr = fmt.Sprintf(" (built %s)", BuildDate)
	}
	return fmt.Sprintf("OneAuth %s-%s%s [%s/%s %s]", Version, GitCommit, dateStr, runtime.GOOS, runtime.GOARCH, runtime.Version())
}

// Short 返回简明版本号
func Short() string {
	return Version
}
