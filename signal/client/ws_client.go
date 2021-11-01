package client

import (
	"context"
	"github.com/wiretrustee/wiretrustee/signal/proto"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

//WebsocketClient is a Signal server websocket client (alternative to the original gRPC Client)
type WebsocketClient struct {
	key wgtypes.Key
	ctx context.Context
}

func NewWebsocketClient(ctx context.Context, addr string, wgPrivateKey wgtypes.Key) (*WebsocketClient, error) {
	return &WebsocketClient{
		key: wgPrivateKey,
		ctx: ctx,
	}, nil
}

func (c *WebsocketClient) Close() error {
	return nil
}

func (c *WebsocketClient) Receive(msgHandler func(msg *proto.Message) error) {

}
func (c *WebsocketClient) SendToStream(msg *proto.EncryptedMessage) error {
	return nil
}
func (c *WebsocketClient) Send(msg *proto.Message) error {
	return nil
}

func (c *WebsocketClient) WaitConnected() {

}
