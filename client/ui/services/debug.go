//go:build !android && !ios && !freebsd && !js

package services

import (
	"context"
	"fmt"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/version"
)

type DebugBundleParams struct {
	Anonymize    bool   `json:"anonymize"`
	SystemInfo   bool   `json:"systemInfo"`
	UploadURL    string `json:"uploadUrl"`
	LogFileCount uint32 `json:"logFileCount"`
}

// DebugBundleResult: Path is set for local-only bundles, UploadedKey on upload
// success, UploadFailureReason on upload failure.
type DebugBundleResult struct {
	Path                string `json:"path"`
	UploadedKey         string `json:"uploadedKey"`
	UploadFailureReason string `json:"uploadFailureReason"`
}

// LogLevel carries a logrus level name: "error", "warn", "info", "debug", "trace".
type LogLevel struct {
	Level string `json:"level"`
}

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

// RevealFile opens the OS file manager focused on path. Needed because Wails'
// Browser.OpenURL refuses non-http(s) schemes like file://.
func (s *Debug) RevealFile(_ context.Context, path string) error {
	if path == "" {
		return fmt.Errorf("empty path")
	}
	return revealFile(path)
}

// RegisterUILog reports the GUI log path to the daemon for bundle collection;
// the daemon runs as root and can't resolve the user's config dir. Called on
// each daemon (re)connect.
func (s *Debug) RegisterUILog(ctx context.Context, path string) error {
	cli, err := s.conn.Client()
	if err != nil {
		return err
	}
	_, err = cli.RegisterUILog(ctx, &proto.RegisterUILogRequest{Path: path})
	return err
}

func (s *Debug) StartBundleCapture(ctx context.Context, timeoutSeconds int32) error {
	cli, err := s.conn.Client()
	if err != nil {
		return err
	}
	req := &proto.StartBundleCaptureRequest{}
	if timeoutSeconds > 0 {
		req.Timeout = durationpb.New(time.Duration(timeoutSeconds) * time.Second)
	}
	_, err = cli.StartBundleCapture(ctx, req)
	return err
}

func (s *Debug) StopBundleCapture(ctx context.Context) error {
	cli, err := s.conn.Client()
	if err != nil {
		return err
	}
	_, err = cli.StopBundleCapture(ctx, &proto.StopBundleCaptureRequest{})
	return err
}

func (s *Debug) SetLogLevel(ctx context.Context, lvl LogLevel) error {
	cli, err := s.conn.Client()
	if err != nil {
		return err
	}
	// proto.LogLevel_value keys are upper-case enum names; callers pass
	// lowercase logrus names. Upper-case before lookup or a valid level
	// silently falls through to INFO.
	level, ok := proto.LogLevel_value[strings.ToUpper(lvl.Level)]
	if !ok {
		level = int32(proto.LogLevel_INFO)
	}
	_, err = cli.SetLogLevel(ctx, &proto.SetLogLevelRequest{Level: proto.LogLevel(level)})
	return err
}
