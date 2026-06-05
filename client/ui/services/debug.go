//go:build !android && !ios && !freebsd && !js

package services

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/version"
)

// DebugBundleParams configures what the daemon collects when generating a
// debug bundle.
type DebugBundleParams struct {
	Anonymize    bool   `json:"anonymize"`
	SystemInfo   bool   `json:"systemInfo"`
	UploadURL    string `json:"uploadUrl"`
	LogFileCount uint32 `json:"logFileCount"`
}

// DebugBundleResult mirrors DebugBundleResponse — Path is set on local-only
// bundles, UploadedKey on successful uploads, UploadFailureReason on failed
// uploads.
type DebugBundleResult struct {
	Path                string `json:"path"`
	UploadedKey         string `json:"uploadedKey"`
	UploadFailureReason string `json:"uploadFailureReason"`
}

// LogLevel is a single log-level value the daemon understands ("error",
// "warn", "info", "debug", "trace").
type LogLevel struct {
	Level string `json:"level"`
}

// Debug groups debug / log-level / packet-trace RPCs.
type Debug struct {
	conn DaemonConn
}

func NewDebug(conn DaemonConn) *Debug {
	return &Debug{conn: conn}
}

func (s *Debug) Bundle(ctx context.Context, p DebugBundleParams) (DebugBundleResult, error) {
	cli, err := s.conn.Client()
	if err != nil {
		return DebugBundleResult{}, err
	}
	resp, err := cli.DebugBundle(ctx, &proto.DebugBundleRequest{
		Anonymize:    p.Anonymize,
		SystemInfo:   p.SystemInfo,
		UploadURL:    p.UploadURL,
		LogFileCount: p.LogFileCount,
		CliVersion:   version.NetbirdVersion(),
	})
	if err != nil {
		return DebugBundleResult{}, err
	}
	return DebugBundleResult{
		Path:                resp.GetPath(),
		UploadedKey:         resp.GetUploadedKey(),
		UploadFailureReason: resp.GetUploadFailureReason(),
	}, nil
}

func (s *Debug) GetLogLevel(ctx context.Context) (LogLevel, error) {
	cli, err := s.conn.Client()
	if err != nil {
		return LogLevel{}, err
	}
	resp, err := cli.GetLogLevel(ctx, &proto.GetLogLevelRequest{})
	if err != nil {
		return LogLevel{}, err
	}
	return LogLevel{Level: resp.GetLevel().String()}, nil
}

// RevealFile opens the OS file manager focused on the given path. Wails'
// Browser.OpenURL refuses non-http(s) schemes, so the UI calls this binding
// instead of constructing a file:// URL.
func (s *Debug) RevealFile(_ context.Context, path string) error {
	if path == "" {
		return fmt.Errorf("empty path")
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", "-R", path)
	case "windows":
		cmd = exec.Command("explorer", "/select,"+path)
	default:
		cmd = exec.Command("xdg-open", filepath.Dir(path))
	}
	return cmd.Start()
}

func (s *Debug) SetLogLevel(ctx context.Context, lvl LogLevel) error {
	cli, err := s.conn.Client()
	if err != nil {
		return err
	}
	level, ok := proto.LogLevel_value[lvl.Level]
	if !ok {
		level = int32(proto.LogLevel_INFO)
	}
	_, err = cli.SetLogLevel(ctx, &proto.SetLogLevelRequest{Level: proto.LogLevel(level)})
	return err
}
