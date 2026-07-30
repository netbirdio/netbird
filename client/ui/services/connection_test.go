//go:build !android && !ios && !freebsd && !js

package services

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/netbirdio/netbird/client/proto"
)

// fakeDaemonClient records the Down/Up calls Reconnect makes. Embedding the
// generated interface keeps the fake to the two RPCs under test.
type fakeDaemonClient struct {
	proto.DaemonServiceClient

	downErr error
	upErr   error
	calls   []string
	// onDown runs after Down is recorded, to simulate a Disconnect or a quit
	// landing while the teardown is still in flight.
	onDown func()
}

func (c *fakeDaemonClient) Down(context.Context, *proto.DownRequest, ...grpc.CallOption) (*proto.DownResponse, error) {
	c.calls = append(c.calls, "down")
	if c.onDown != nil {
		c.onDown()
	}
	if c.downErr != nil {
		return nil, c.downErr
	}
	return &proto.DownResponse{}, nil
}

func (c *fakeDaemonClient) Up(context.Context, *proto.UpRequest, ...grpc.CallOption) (*proto.UpResponse, error) {
	c.calls = append(c.calls, "up")
	if c.upErr != nil {
		return nil, c.upErr
	}
	return &proto.UpResponse{}, nil
}

type fakeDaemonConn struct{ client proto.DaemonServiceClient }

func (c fakeDaemonConn) Client() (proto.DaemonServiceClient, error) { return c.client, nil }

func TestConnectionReconnectSendsDownThenUp(t *testing.T) {
	client := &fakeDaemonClient{}
	conn := NewConnection(fakeDaemonConn{client: client}, nil, nil)

	require.NoError(t, conn.Reconnect(context.Background()))
	require.Equal(t, []string{"down", "up"}, client.calls)
}

func TestConnectionReconnectFailedDownSkipsUp(t *testing.T) {
	client := &fakeDaemonClient{downErr: errors.New("teardown refused")}
	conn := NewConnection(fakeDaemonConn{client: client}, nil, nil)

	require.Error(t, conn.Reconnect(context.Background()))
	require.Equal(t, []string{"down"}, client.calls,
		"Up must not stack on a session that is still up")
}

func TestConnectionReconnectCancelDuringDownSkipsUp(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// A tray Disconnect or a quit cancels the round trip mid-teardown; the Up
	// must not bring the session back afterwards.
	client := &fakeDaemonClient{onDown: cancel}
	conn := NewConnection(fakeDaemonConn{client: client}, nil, nil)

	require.ErrorIs(t, conn.Reconnect(ctx), context.Canceled)
	require.Equal(t, []string{"down"}, client.calls)
}
