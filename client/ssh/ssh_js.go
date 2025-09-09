package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"

	"golang.org/x/crypto/ssh"
)

var ErrSSHNotSupported = errors.New("SSH is not supported in WASM environment")

// Server is a dummy SSH server interface for WASM.
type Server interface {
	Start() error
	Stop() error
	EnableSSH(enabled bool)
	AddAuthorizedKey(peer string, key string) error
	RemoveAuthorizedKey(key string)
}

type dummyServer struct{}

func DefaultSSHServer(hostKeyPEM []byte, addr string) (Server, error) {
	return &dummyServer{}, nil
}

func NewServer(addr string) Server {
	return &dummyServer{}
}

func (s *dummyServer) Start() error {
	return ErrSSHNotSupported
}

func (s *dummyServer) Stop() error {
	return nil
}

func (s *dummyServer) EnableSSH(enabled bool) {
}

func (s *dummyServer) AddAuthorizedKey(peer string, key string) error {
	return nil
}

func (s *dummyServer) RemoveAuthorizedKey(key string) {
}

type Client struct{}

func NewClient(ctx context.Context, addr string, config interface{}, recorder *SessionRecorder) (*Client, error) {
	return nil, ErrSSHNotSupported
}

func (c *Client) Close() error {
	return nil
}

func (c *Client) Run(command []string) error {
	return ErrSSHNotSupported
}

type SessionRecorder struct{}

func NewSessionRecorder() *SessionRecorder {
	return &SessionRecorder{}
}

func (r *SessionRecorder) Record(session string, data []byte) {
}

func GetUserShell() string {
	return "/bin/sh"
}

func LookupUserInfo(username string) (string, string, error) {
	return "", "", ErrSSHNotSupported
}

const DefaultSSHPort = 44338

const ED25519 = "ed25519"

func isRoot() bool {
	return false
}

func GeneratePrivateKey(keyType string) ([]byte, error) {
	if keyType != ED25519 {
		return nil, errors.New("only ED25519 keys are supported in WASM")
	}

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	pemBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8Bytes,
	}

	pemBytes := pem.EncodeToMemory(pemBlock)
	return pemBytes, nil
}

func GeneratePublicKey(privateKey []byte) ([]byte, error) {
	signer, err := ssh.ParsePrivateKey(privateKey)
	if err != nil {
		block, _ := pem.Decode(privateKey)
		if block != nil {
			key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			signer, err = ssh.NewSignerFromKey(key)
			if err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}

	pubKeyBytes := ssh.MarshalAuthorizedKey(signer.PublicKey())
	return []byte(strings.TrimSpace(string(pubKeyBytes))), nil
}
