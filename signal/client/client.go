package client

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/netbirdio/netbird/signal/proto"
	"github.com/netbirdio/netbird/version"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// A set of tools to exchange connection details (Wireguard endpoints) with the remote peer.

// Status is the status of the client
type Status string

const StreamConnected Status = "Connected"
const StreamDisconnected Status = "Disconnected"

const (
	// DirectCheck indicates support to direct mode checks
	DirectCheck uint32 = 1
)

type Client interface {
	io.Closer
	StreamConnected() bool
	GetStatus() Status
	Receive(ctx context.Context, msgHandler func(msg *proto.Message) error) error
	Ready() bool
	IsHealthy() bool
	WaitStreamConnected()
	SendToStream(msg *proto.EncryptedMessage) error
	Send(msg *proto.Message) error
}

// UnMarshalCredential parses the credentials from the message and returns a Credential instance
func UnMarshalCredential(msg *proto.Message) (*Credential, error) {

	credential := strings.Split(msg.GetBody().GetPayload(), ":")
	if len(credential) != 2 {
		return nil, fmt.Errorf("error parsing message body %s", msg.Body)
	}
	return &Credential{
		UFrag: credential[0],
		Pwd:   credential[1],
	}, nil
}

// MarshalCredential marshal a Credential instance and returns a Message object
func MarshalCredential(myKey wgtypes.Key, myPort int, remoteKey wgtypes.Key, credential *Credential, t proto.Body_Type,
	rosenpassPubKey []byte, rosenpassAddr string) (*proto.Message, error) {
	return &proto.Message{
		Key:       myKey.PublicKey().String(),
		RemoteKey: remoteKey.String(),
		Body: &proto.Body{
			Type:           t,
			Payload:        fmt.Sprintf("%s:%s", credential.UFrag, credential.Pwd),
			WgListenPort:   uint32(myPort),
			NetBirdVersion: version.NetbirdVersion(),
			RosenpassConfig: &proto.RosenpassConfig{
				RosenpassPubKey:     rosenpassPubKey,
				RosenpassServerAddr: rosenpassAddr,
			},
		},
	}, nil
}

// Credential is an instance of a GrpcClient's Credential
type Credential struct {
	UFrag string
	Pwd   string
}
