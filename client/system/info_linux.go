package system

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"google.golang.org/grpc/metadata"
)

func GetInfo(ctx context.Context) *Info {
	info := _getInfo()
	for strings.Contains(info, "broken pipe") {
		info = _getInfo()
		time.Sleep(500 * time.Millisecond)
	}

	releaseInfo := _getReleaseInfo()
	for strings.Contains(info, "broken pipe") {
		releaseInfo = _getReleaseInfo()
		time.Sleep(500 * time.Millisecond)
	}

	osRelease := strings.Split(releaseInfo, "\n")
	var osName string
	var osVer string
	for _, s := range osRelease {
		if strings.HasPrefix(s, "NAME=") {
			osName = strings.Split(s, "=")[1]
			osName = strings.ReplaceAll(osName, "\"", "")
		} else if strings.HasPrefix(s, "VERSION_ID=") {
			osVer = strings.Split(s, "=")[1]
			osVer = strings.ReplaceAll(osVer, "\"", "")
		}
	}

	osStr := strings.Replace(info, "\n", "", -1)
	osStr = strings.Replace(osStr, "\r\n", "", -1)
	osInfo := strings.Split(osStr, " ")
	if osName == "" {
		osName = osInfo[3]
	}
	gio := &Info{Kernel: osInfo[0], Core: osInfo[1], Platform: osInfo[2], OS: osName, OSVersion: osVer, GoOS: runtime.GOOS, CPUs: runtime.NumCPU()}
	gio.Hostname, _ = os.Hostname()
	gio.WiretrusteeVersion = WiretrusteeVersion()
	gio.UIVersion = extractUserAgent(ctx)

	return gio
}

func extractUserAgent(ctx context.Context) string {
	mD, ok := metadata.FromIncomingContext(ctx)
	if ok {
		agent, ok := mD["netbird-desktop-ui"]
		if ok {
			return agent[0]
		}
	}
	return ""
}

func _getInfo() string {
	cmd := exec.Command("uname", "-srio")
	cmd.Stdin = strings.NewReader("some")
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		fmt.Println("getInfo:", err)
	}
	return out.String()
}
