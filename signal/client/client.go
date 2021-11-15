package client

import (
	"fmt"
	"github.com/wiretrustee/wiretrustee/encryption"
	"github.com/wiretrustee/wiretrustee/signal/proto"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"strings"
)

// A set of tools to exchange connection details (Wireguard endpoints) with the remote peer.

// Status is the status of the client
type Status string

const StreamConnected Status = "Connected"
const StreamDisconnected Status = "Disconnected"

// Client is an interface describing Signal client
type Client interface {
	// Receive handles incoming messages from the Signal service
	Receive(msgHandler func(msg *proto.Message) error) error
	Close() error
	// Send sends a message to the Signal service (just one time rpc call, not stream)
	Send(msg *proto.Message) error
	// SendToStream sends a message to the Signal service through a connected stream
	SendToStream(msg *proto.EncryptedMessage) error
	// WaitStreamConnected blocks until client is connected to the Signal stream
	WaitStreamConnected()
	GetStatus() Status
}

// decryptMessage decrypts the body of the msg using Wireguard private key and Remote peer's public key
func decryptMessage(msg *proto.EncryptedMessage, wgPrivateKey wgtypes.Key) (*proto.Message, error) {
	remoteKey, err := wgtypes.ParseKey(msg.GetKey())
	if err != nil {
		return nil, err
	}

	body := &proto.Body{}
	err = encryption.DecryptMessage(remoteKey, wgPrivateKey, msg.GetBody(), body)
	if err != nil {
		return nil, err
	}

	return &proto.Message{
		Key:       msg.Key,
		RemoteKey: msg.RemoteKey,
		Body:      body,
	}, nil
}

// encryptMessage encrypts the body of the msg using Wireguard private key and Remote peer's public key
func encryptMessage(msg *proto.Message, wgPrivateKey wgtypes.Key) (*proto.EncryptedMessage, error) {

	remoteKey, err := wgtypes.ParseKey(msg.RemoteKey)
	if err != nil {
		return nil, err
	}

	encryptedBody, err := encryption.EncryptMessage(remoteKey, wgPrivateKey, msg.Body)
	if err != nil {
		return nil, err
	}

	return &proto.EncryptedMessage{
		Key:       msg.GetKey(),
		RemoteKey: msg.GetRemoteKey(),
		Body:      encryptedBody,
	}, nil
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
