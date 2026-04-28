//go:build !android && !ios && !freebsd && !js

package services

import (
	"context"

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
