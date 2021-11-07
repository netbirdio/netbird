package client

import (
	"context"
	"encoding/base64"
	pb "github.com/golang/protobuf/proto"
	log "github.com/sirupsen/logrus"
	"github.com/wiretrustee/wiretrustee/signal/proto"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"nhooyr.io/websocket"
	"time"
)

//WebsocketClient is a Signal server websocket client (alternative to the original gRPC Client)
type WebsocketClient struct {
	key  wgtypes.Key
	ctx  context.Context
	conn *websocket.Conn
}

func NewWebsocketClient(ctx context.Context, endpoint string, wgPrivateKey wgtypes.Key) (*WebsocketClient, error) {

	sigCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// generate peer identifier from our public key and base64 encode it because it will be transferred via URL param
	peerId := base64.URLEncoding.EncodeToString([]byte(wgPrivateKey.PublicKey().String()))
	conn, res, err := websocket.Dial(sigCtx, endpoint+"?id="+peerId, &websocket.DialOptions{})
	if err != nil {
		log.Errorf("failed to connect to the Signal Websocket server %v - %v", err, res)
		return nil, err
	}

	return &WebsocketClient{
		key:  wgPrivateKey,
		ctx:  ctx,
		conn: conn,
	}, nil
}

func (c *WebsocketClient) Close() error {
	return c.conn.Close(websocket.StatusNormalClosure, "close")
}

func (c *WebsocketClient) Receive(msgHandler func(msg *proto.Message) error) error {
	for {
		_, byteMsg, err := c.conn.Read(c.ctx)
		if err != nil {
			log.Errorf("failed reading message from Signal Websocket %v", err)
			time.Sleep(2 * time.Second)
			//todo propagate to the upper layer and retry
			return err
		}

		encryptedMsg := &proto.EncryptedMessage{}
		err = pb.Unmarshal(byteMsg, encryptedMsg)
		if err != nil {
			log.Errorf("failed unmarshalling message from Signal Websocket %v", err)
			continue
		}

		remotePubKey := encryptedMsg.Key

		log.Debugf("received a new message from Peer %s received via Websocket", remotePubKey)

		decryptedMsg, err := decryptMessage(encryptedMsg, c.key)
		if err != nil {
			log.Errorf("failed decrypting a message from peer %s received via Websocket %v", remotePubKey, err)
		}

		err = msgHandler(decryptedMsg)
		if err != nil {
			log.Errorf("error while handling message from peer %s %v", remotePubKey, err)
			//todo send something??
		}
	}
}
func (c *WebsocketClient) SendToStream(msg *proto.EncryptedMessage) error {

	bytesMsg, err := pb.Marshal(msg)
	if err != nil {
		log.Errorf("failed marshalling message %v", err)
		return err
	}

	return c.conn.Write(c.ctx, websocket.MessageBinary, bytesMsg)
}

func (c *WebsocketClient) Send(msg *proto.Message) error {

	encryptedMessage, err := encryptMessage(msg, c.key)
	if err != nil {
		return err
	}

	return c.SendToStream(encryptedMessage)

}

func (c *WebsocketClient) WaitStreamConnected() {

}
