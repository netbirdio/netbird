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
	out := _getInfo()
	for strings.Contains(out, "broken pipe") {
		out = _getInfo()
		time.Sleep(500 * time.Millisecond)
	}
	osStr := strings.Replace(out, "\n", "", -1)
	osStr = strings.Replace(osStr, "\r\n", "", -1)
	osInfo := strings.Split(osStr, " ")
	gio := &Info{Kernel: osInfo[0], OSVersion: osInfo[1], Core: osInfo[1], Platform: osInfo[2], OS: osInfo[0], GoOS: runtime.GOOS, CPUs: runtime.NumCPU()}
	gio.Hostname, _ = os.Hostname()
	gio.WiretrusteeVersion = WiretrusteeVersion()
	gio.UIVersion = extractUserAgent(ctx)

	return gio
}

func _getInfo() string {
	cmd := exec.Command("uname", "-srm")
	cmd.Stdin = strings.NewReader("some input")
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

func extractUserAgent(ctx context.Context) string {
	mD, ok := metadata.FromIncomingContext(ctx)
	if ok {
		agent, ok := mD["user-agent"]
		if ok {
			return agent[0]
		}
	}
	return ""
}
