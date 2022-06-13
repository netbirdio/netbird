package ssh

import (
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
	server, err := NewSSHServer(key, "localhost:")
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

	k, ok := server.authorizedKeys["remotePeer"]
	assert.True(t, ok, "expected remotePeer key to be found in authorizedKeys")

	assert.Equal(t, string(remotePubKey), strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k))))
}

func TestServer_RemoveAuthorizedKey(t *testing.T) {
	key, err := GeneratePrivateKey(ED25519)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewSSHServer(key, "localhost:")
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
	assert.False(t, ok, "expected remotePeer's SSH key to be removed")
}
