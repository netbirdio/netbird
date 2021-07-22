package signal

import (
	"github.com/wiretrustee/wiretrustee/common"
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

	encryptedMessage, err := common.Encrypt(bytesMsg, peerBKey.PublicKey(), peerAKey)
	if err != nil {
		t.Error(err)
		return
	}

	decryptedMessage, err := common.Decrypt(encryptedMessage, peerAKey.PublicKey(), peerBKey)
	if err != nil {
		t.Error(err)
		return
	}

	if string(decryptedMessage) != strMsg {
		t.Error()
	}

}
