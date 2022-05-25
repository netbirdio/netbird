package system

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"google.golang.org/grpc/metadata"
)

func GetInfo(ctx context.Context) *Info {
	cmd := exec.Command("cmd", "ver")
	cmd.Stdin = strings.NewReader("some")
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		panic(err)
	}
	osStr := strings.Replace(out.String(), "\n", "", -1)
	osStr = strings.Replace(osStr, "\r\n", "", -1)
	tmp1 := strings.Index(osStr, "[Version")
	tmp2 := strings.Index(osStr, "]")
	var ver string
	if tmp1 == -1 || tmp2 == -1 {
		ver = "unknown"
	} else {
		ver = osStr[tmp1+9 : tmp2]
	}
	gio := &Info{Kernel: "windows", OSVersion: ver, Core: ver, Platform: "unknown", OS: "windows", GoOS: runtime.GOOS, CPUs: runtime.NumCPU()}
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
