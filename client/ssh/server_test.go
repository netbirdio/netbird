package ssh

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ssh"
	"strings"
	"testing"
)

func TestServer_AddAuthorizedKey(t *testing.T) {
	key, err := GeneratePrivateKey(ED25519)
	if err != nil {
		t.Fatal(err)
	}
	server, err := newDefaultServer(key, "localhost:")
	if err != nil {
		t.Fatal(err)
	}

	// add multiple keys
	keys := map[string][]byte{}
	for i := 0; i < 10; i++ {
		peer := fmt.Sprintf("%s-%d", "remotePeer", i)
		remotePrivKey, err := GeneratePrivateKey(ED25519)
		if err != nil {
			t.Fatal(err)
		}
		remotePubKey, err := GeneratePublicKey(remotePrivKey)
		if err != nil {
			t.Fatal(err)
		}

		err = server.AddAuthorizedKey(peer, string(remotePubKey))
		if err != nil {
			t.Error(err)
		}
		keys[peer] = remotePubKey
	}

	// make sure that all keys have been added
	for peer, remotePubKey := range keys {
		k, ok := server.authorizedKeys[peer]
		assert.True(t, ok, "expecting remotePeer key to be found in authorizedKeys")

		assert.Equal(t, string(remotePubKey), strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k))))
	}

}

func TestServer_RemoveAuthorizedKey(t *testing.T) {
	key, err := GeneratePrivateKey(ED25519)
	if err != nil {
		t.Fatal(err)
	}
	server, err := newDefaultServer(key, "localhost:")
	if err != nil {
		t.Fatal(err)
	}

	remotePrivKey, err := GeneratePrivateKey(ED25519)
	if err != nil {
		t.Fatal(err)
	}
	remotePubKey, err := GeneratePublicKey(remotePrivKey)
	if err != nil {
		t.Fatal(err)
	}

	err = server.AddAuthorizedKey("remotePeer", string(remotePubKey))
	if err != nil {
		t.Error(err)
	}

	server.RemoveAuthorizedKey("remotePeer")

	_, ok := server.authorizedKeys["remotePeer"]
	assert.False(t, ok, "expecting remotePeer's SSH key to be removed")
}

func TestServer_PubKeyHandler(t *testing.T) {
	key, err := GeneratePrivateKey(ED25519)
	if err != nil {
		t.Fatal(err)
	}
	server, err := newDefaultServer(key, "localhost:")
	if err != nil {
		t.Fatal(err)
	}

	var keys []ssh.PublicKey
	for i := 0; i < 10; i++ {
		peer := fmt.Sprintf("%s-%d", "remotePeer", i)
		remotePrivKey, err := GeneratePrivateKey(ED25519)
		if err != nil {
			t.Fatal(err)
		}
		remotePubKey, err := GeneratePublicKey(remotePrivKey)
		if err != nil {
			t.Fatal(err)
		}

		remoteParsedPubKey, _, _, _, err := ssh.ParseAuthorizedKey(remotePubKey)
		if err != nil {
			t.Fatal(err)
		}

		err = server.AddAuthorizedKey(peer, string(remotePubKey))
		if err != nil {
			t.Error(err)
		}
		keys = append(keys, remoteParsedPubKey)
	}

	for _, key := range keys {
		accepted := server.publicKeyHandler(nil, key)

		assert.Truef(t, accepted, "expecting SSH connection to be accepted for a given SSH key %s", string(ssh.MarshalAuthorizedKey(key)))
	}

}
