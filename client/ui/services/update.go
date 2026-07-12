//go:build !android && !ios && !freebsd && !js

package services

import (
	"context"
	"time"

	"github.com/wailsapp/wails/v3/pkg/application"

	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/client/ui/updater"
)

// UpdateResult mirrors TriggerUpdateResponse.
type UpdateResult struct {
	Success  bool   `json:"success"`
	ErrorMsg string `json:"errorMsg"`
}

// Update is the Wails-bound facade over the daemon's update RPCs. The state
// machine and push event live in client/ui/updater.
type Update struct {
	conn   DaemonConn
	holder *updater.Holder
}

func NewUpdate(conn DaemonConn, holder *updater.Holder) *Update {
	return &Update{conn: conn, holder: holder}
}

func (s *Update) GetState() updater.State {
	return s.holder.Get()
}

// Quit exits the app. Scheduled off the calling goroutine so the JS caller's
// response returns before the runtime tears down.
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
