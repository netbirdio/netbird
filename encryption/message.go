package encryption

import (
	pb "github.com/golang/protobuf/proto" //nolint
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// EncryptMessage encrypts a body of the given protobuf Message
func EncryptMessage(remotePubKey wgtypes.Key, ourPrivateKey wgtypes.Key, message pb.Message) ([]byte, error) {
	byteResp, err := pb.Marshal(message)
	if err != nil {
		log.Errorf("failed marshalling message %v", err)
		return nil, err
	}

	encryptedBytes, err := Encrypt(byteResp, remotePubKey, ourPrivateKey)
	if err != nil {
		log.Errorf("failed encrypting SyncResponse %v", err)
		return nil, err
	}

	return encryptedBytes, nil
}

// DecryptMessage decrypts an encrypted message into given protobuf Message
func DecryptMessage(remotePubKey wgtypes.Key, ourPrivateKey wgtypes.Key, encryptedMessage []byte, message pb.Message) error {
	decrypted, err := Decrypt(encryptedMessage, remotePubKey, ourPrivateKey)
	if err != nil {
		log.Warnf("error while decrypting Sync request message from peer %s", remotePubKey.String())
		return err
	}

	err = pb.Unmarshal(decrypted, message)
	if err != nil {
		log.Warnf("error while umarshalling Sync request message from peer %s", remotePubKey.String())
		return err
	}
	return nil
}
