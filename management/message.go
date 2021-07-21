package management

import (
	pb "github.com/golang/protobuf/proto" //nolint
	log "github.com/sirupsen/logrus"
	"github.com/wiretrustee/wiretrustee/management/proto"
	"github.com/wiretrustee/wiretrustee/signal"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// EncryptMessage encrypts a body of the given pn.Message and wraps into proto.EncryptedMessage
func EncryptMessage(peerKey wgtypes.Key, serverPrivateKey wgtypes.Key, message pb.Message) (*proto.EncryptedMessage, error) {
	byteResp, err := pb.Marshal(message)
	if err != nil {
		log.Errorf("failed marshalling message %v", err)
		return nil, err
	}

	encryptedBytes, err := signal.Encrypt(byteResp, peerKey, serverPrivateKey)
	if err != nil {
		log.Errorf("failed encrypting SyncResponse %v", err)
		return nil, err
	}

	return &proto.EncryptedMessage{
		WgPubKey: serverPrivateKey.PublicKey().String(),
		Body:     encryptedBytes}, nil
}

//DecryptMessage decrypts an encrypted message (proto.EncryptedMessage)
func DecryptMessage(peerKey wgtypes.Key, serverPrivateKey wgtypes.Key, encryptedMessage *proto.EncryptedMessage, message pb.Message) error {
	decrypted, err := signal.Decrypt(encryptedMessage.Body, peerKey, serverPrivateKey)
	if err != nil {
		log.Warnf("error while decrypting Sync request message from peer %s", peerKey.String())
		return err
	}

	err = pb.Unmarshal(decrypted, message)
	if err != nil {
		log.Warnf("error while umarshalling Sync request message from peer %s", peerKey.String())
		return err
	}
	return nil
}
