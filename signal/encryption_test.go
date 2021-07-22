package signal

import (
	"github.com/wiretrustee/wiretrustee/encryption"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	strMsg := "message to encrypt"
	bytesMsg := []byte(strMsg)

	peerAKey, err := wgtypes.GenerateKey()
	if err != nil {
		t.Error()
		return
	}

	peerBKey, err := wgtypes.GenerateKey()
	if err != nil {
		t.Error()
		return
	}

	encryptedMessage, err := encryption.Encrypt(bytesMsg, peerBKey.PublicKey(), peerAKey)
	if err != nil {
		t.Error(err)
		return
	}

	decryptedMessage, err := encryption.Decrypt(encryptedMessage, peerAKey.PublicKey(), peerBKey)
	if err != nil {
		t.Error(err)
		return
	}

	if string(decryptedMessage) != strMsg {
		t.Error()
	}

}
