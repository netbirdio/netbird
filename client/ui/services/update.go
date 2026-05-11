//go:build !android && !ios && !freebsd && !js

package services

import (
	"context"
	"time"

	"github.com/wailsapp/wails/v3/pkg/application"

	"github.com/netbirdio/netbird/client/proto"
)

// UpdateResult mirrors TriggerUpdateResponse: Success false carries an error
// message in ErrorMsg.
type UpdateResult struct {
	Success  bool   `json:"success"`
	ErrorMsg string `json:"errorMsg"`
}

// Update groups the RPCs that drive the enforced-update install flow.
type Update struct {
	conn DaemonConn
}

func NewUpdate(conn DaemonConn) *Update {
	return &Update{conn: conn}
}

// Quit asks the host application to exit. The /update page calls this once
// the daemon-side installer has reported success, mirroring the legacy
// Fyne UI's app.Quit() in showInstallerResult. Schedules the actual exit
// off the calling goroutine so the JS-side caller's response can return
// before the runtime tears down.
func (s *Update) Quit() {
	go func() {
		time.Sleep(100 * time.Millisecond)
		application.Get().Quit()
	}()
}

func (s *Update) Trigger(ctx context.Context) (UpdateResult, error) {
	cli, err := s.conn.Client()
	if err != nil {
		return UpdateResult{}, err
	}
	resp, err := cli.TriggerUpdate(ctx, &proto.TriggerUpdateRequest{})
	if err != nil {
		return UpdateResult{}, err
	}
	return UpdateResult{
		Success:  resp.GetSuccess(),
		ErrorMsg: resp.GetErrorMsg(),
	}, nil
}

func (s *Update) GetInstallerResult(ctx context.Context) (UpdateResult, error) {
	cli, err := s.conn.Client()
	if err != nil {
		return UpdateResult{}, err
	}
	resp, err := cli.GetInstallerResult(ctx, &proto.InstallerResultRequest{})
	if err != nil {
		return UpdateResult{}, err
	}
	return UpdateResult{
		Success:  resp.GetSuccess(),
		ErrorMsg: resp.GetErrorMsg(),
	}, nil
}
