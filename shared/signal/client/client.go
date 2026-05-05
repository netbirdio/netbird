package client

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"strings"

	"github.com/netbirdio/netbird/shared/signal/proto"
	"github.com/netbirdio/netbird/version"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// A set of tools to exchange connection details (Wireguard endpoints) with the remote peer.

const (
	StreamConnected    Status = "Connected"
	StreamDisconnected Status = "Disconnected"

	// DirectCheck indicates support to direct mode checks
	DirectCheck uint32 = 1
)

// Status is the status of the client
type Status string

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
	SetOnReconnectedListener(func())
}

// Credential is an instance of a GrpcClient's Credential
type Credential struct {
	UFrag string
	Pwd   string
}

// CredentialPayload bundles the fields of a signal Body for MarshalCredential.
type CredentialPayload struct {
	Type            proto.Body_Type
	WgListenPort    int
	Credential      *Credential
	RosenpassPubKey []byte
	RosenpassAddr   string
	RelaySrvAddress string
	RelaySrvIP      netip.Addr
	SessionID       []byte
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
func MarshalCredential(myKey wgtypes.Key, remoteKey string, p CredentialPayload) (*proto.Message, error) {
	body := &proto.Body{
		Type:           p.Type,
		Payload:        fmt.Sprintf("%s:%s", p.Credential.UFrag, p.Credential.Pwd),
		WgListenPort:   uint32(p.WgListenPort),
		NetBirdVersion: version.NetbirdVersion(),
		RosenpassConfig: &proto.RosenpassConfig{
			RosenpassPubKey:     p.RosenpassPubKey,
			RosenpassServerAddr: p.RosenpassAddr,
		},
		SessionId: p.SessionID,
	}
	if p.RelaySrvAddress != "" {
		body.RelayServerAddress = &p.RelaySrvAddress
	}
	if p.RelaySrvIP.IsValid() {
		body.RelayServerIP = p.RelaySrvIP.Unmap().AsSlice()
	}
	return &proto.Message{
		Key:       myKey.PublicKey().String(),
		RemoteKey: remoteKey,
		Body:      body,
	}, nil
}
