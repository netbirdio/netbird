package client

import (
	"fmt"
	"github.com/wiretrustee/wiretrustee/signal/proto"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"strings"
)

// A set of tools to exchange connection details (Wireguard endpoints) with the remote peer.

type Client interface {
	Receive(msgHandler func(msg *proto.Message) error)
	Close() error
	Send(msg *proto.Message) error
	SendToStream(msg *proto.EncryptedMessage) error
	WaitConnected()
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
func MarshalCredential(myKey wgtypes.Key, remoteKey wgtypes.Key, credential *Credential, t proto.Body_Type) (*proto.Message, error) {
	return &proto.Message{
		Key:       myKey.PublicKey().String(),
		RemoteKey: remoteKey.String(),
		Body: &proto.Body{
			Type:    t,
			Payload: fmt.Sprintf("%s:%s", credential.UFrag, credential.Pwd),
		},
	}, nil
}

// Credential is an instance of a Client's Credential
type Credential struct {
	UFrag string
	Pwd   string
}
