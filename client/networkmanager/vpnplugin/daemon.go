//go:build linux

package vpnplugin

import (
	"context"

	"google.golang.org/grpc"

	"github.com/netbirdio/netbird/client/networkmanager/nbdaemon"
	nbproto "github.com/netbirdio/netbird/client/proto"
)

// daemonClient wraps a gRPC connection to the netbird daemon.
type daemonClient struct {
	conn   *grpc.ClientConn
	client nbproto.DaemonServiceClient
}

// dialDaemon connects to the netbird daemon over its control socket.
func dialDaemon(ctx context.Context) (*daemonClient, error) {
	conn, err := nbdaemon.Dial()
	if err != nil {
		return nil, err
	}
	return &daemonClient{conn: conn, client: nbproto.NewDaemonServiceClient(conn)}, nil
}

func (d *daemonClient) Close() error {
	return d.conn.Close()
}

func (d *daemonClient) setConfig(ctx context.Context, req *nbproto.SetConfigRequest) error {
	_, err := d.client.SetConfig(ctx, req)
	return err
}

func (d *daemonClient) login(ctx context.Context, req *nbproto.LoginRequest) (*nbproto.LoginResponse, error) {
	return d.client.Login(ctx, req)
}

func (d *daemonClient) waitSSOLogin(ctx context.Context, userCode string) error {
	_, err := d.client.WaitSSOLogin(ctx, &nbproto.WaitSSOLoginRequest{UserCode: userCode})
	return err
}

func (d *daemonClient) up(ctx context.Context) error {
	_, err := d.client.Up(ctx, &nbproto.UpRequest{Async: true})
	return err
}

func (d *daemonClient) down(ctx context.Context) error {
	_, err := d.client.Down(ctx, &nbproto.DownRequest{})
	return err
}

func (d *daemonClient) subscribeStatus(ctx context.Context) (nbproto.DaemonService_SubscribeStatusClient, error) {
	return d.client.SubscribeStatus(ctx, &nbproto.StatusRequest{GetFullPeerStatus: true})
}

func (d *daemonClient) getConfig(ctx context.Context) (*nbproto.GetConfigResponse, error) {
	return d.client.GetConfig(ctx, &nbproto.GetConfigRequest{})
}
