package client

import (
	"fmt"
	"io"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/system"
	"github.com/netbirdio/netbird/signal/proto"
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

// FeaturesSupport register protocol supported features
type FeaturesSupport struct {
	DirectCheck bool
}

type Client interface {
	io.Closer
	StreamConnected() bool
	GetStatus() Status
	Receive(msgHandler func(msg *proto.Message) error) error
	Ready() bool
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

// MarshalCredential marsharl a Credential instance and returns a Message object
func MarshalCredential(myKey wgtypes.Key, myPort int, remoteKey wgtypes.Key, credential *Credential, t proto.Body_Type) (*proto.Message, error) {
	return &proto.Message{
		Key:       myKey.PublicKey().String(),
		RemoteKey: remoteKey.String(),
		Body: &proto.Body{
			Type:           t,
			Payload:        fmt.Sprintf("%s:%s", credential.UFrag, credential.Pwd),
			WgListenPort:   uint32(myPort),
			NetBirdVersion: system.NetbirdVersion(),
		},
	}, nil
}

// Credential is an instance of a GrpcClient's Credential
type Credential struct {
	UFrag string
	Pwd   string
}

// ParseFeaturesSupported parses a slice of supported features into FeaturesSupport
func ParseFeaturesSupported(featuresMessage []uint32) FeaturesSupport {
	var protoSupport FeaturesSupport
	for _, feature := range featuresMessage {
		if feature == DirectCheck {
			protoSupport.DirectCheck = true
		}
	}
	return protoSupport
}
