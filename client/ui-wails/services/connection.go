//go:build !android && !ios && !freebsd && !js

package services

import (
	"context"

	"github.com/netbirdio/netbird/client/proto"
)

// LoginParams carries the fields the UI sets when starting a login.
type LoginParams struct {
	ProfileName   string `json:"profileName"`
	Username      string `json:"username"`
	ManagementURL string `json:"managementUrl"`
	SetupKey      string `json:"setupKey"`
	PreSharedKey  string `json:"preSharedKey"`
	Hostname      string `json:"hostname"`
	Hint          string `json:"hint"`
}

// LoginResult is the daemon's reply to a Login call.
type LoginResult struct {
	NeedsSSOLogin           bool   `json:"needsSsoLogin"`
	UserCode                string `json:"userCode"`
	VerificationURI         string `json:"verificationUri"`
	VerificationURIComplete string `json:"verificationUriComplete"`
}

// WaitSSOParams carries the fields the UI passes to WaitSSOLogin.
type WaitSSOParams struct {
	UserCode string `json:"userCode"`
	Hostname string `json:"hostname"`
}

// UpParams selects the profile the daemon should bring up.
type UpParams struct {
	ProfileName string `json:"profileName"`
	Username    string `json:"username"`
}

// LogoutParams selects the profile the daemon should log out.
type LogoutParams struct {
	ProfileName string `json:"profileName"`
	Username    string `json:"username"`
}

// Connection groups the daemon RPCs that drive login / connect / disconnect.
type Connection struct {
	conn DaemonConn
}

func NewConnection(conn DaemonConn) *Connection {
	return &Connection{conn: conn}
}

func (s *Connection) Login(ctx context.Context, p LoginParams) (LoginResult, error) {
	cli, err := s.conn.Client()
	if err != nil {
		return LoginResult{}, err
	}
	req := &proto.LoginRequest{
		ManagementUrl: p.ManagementURL,
		SetupKey:      p.SetupKey,
		Hostname:      p.Hostname,
	}
	if p.ProfileName != "" {
		req.ProfileName = ptrStr(p.ProfileName)
	}
	if p.Username != "" {
		req.Username = ptrStr(p.Username)
	}
	if p.PreSharedKey != "" {
		req.OptionalPreSharedKey = ptrStr(p.PreSharedKey)
	}
	if p.Hint != "" {
		req.Hint = ptrStr(p.Hint)
	}

	resp, err := cli.Login(ctx, req)
	if err != nil {
		return LoginResult{}, err
	}
	return LoginResult{
		NeedsSSOLogin:           resp.GetNeedsSSOLogin(),
		UserCode:                resp.GetUserCode(),
		VerificationURI:         resp.GetVerificationURI(),
		VerificationURIComplete: resp.GetVerificationURIComplete(),
	}, nil
}

func (s *Connection) WaitSSOLogin(ctx context.Context, p WaitSSOParams) (string, error) {
	cli, err := s.conn.Client()
	if err != nil {
		return "", err
	}
	resp, err := cli.WaitSSOLogin(ctx, &proto.WaitSSOLoginRequest{
		UserCode: p.UserCode,
		Hostname: p.Hostname,
	})
	if err != nil {
		return "", err
	}
	return resp.GetEmail(), nil
}

func (s *Connection) Up(ctx context.Context, p UpParams) error {
	cli, err := s.conn.Client()
	if err != nil {
		return err
	}
	req := &proto.UpRequest{}
	if p.ProfileName != "" {
		req.ProfileName = ptrStr(p.ProfileName)
	}
	if p.Username != "" {
		req.Username = ptrStr(p.Username)
	}
	_, err = cli.Up(ctx, req)
	return err
}

func (s *Connection) Down(ctx context.Context) error {
	cli, err := s.conn.Client()
	if err != nil {
		return err
	}
	_, err = cli.Down(ctx, &proto.DownRequest{})
	return err
}

func (s *Connection) Logout(ctx context.Context, p LogoutParams) error {
	cli, err := s.conn.Client()
	if err != nil {
		return err
	}
	req := &proto.LogoutRequest{}
	if p.ProfileName != "" {
		req.ProfileName = ptrStr(p.ProfileName)
	}
	if p.Username != "" {
		req.Username = ptrStr(p.Username)
	}
	_, err = cli.Logout(ctx, req)
	return err
}
