package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"
	"io"
	"net"
	"sync"
)

type Server struct {
	listener    net.Listener
	allowedKeys []ssh.PublicKey
	mu          sync.Mutex
}

func (srv *Server) UpdateKeys(newKeys []string) error {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	srv.allowedKeys = make([]ssh.PublicKey, len(newKeys))
	for _, strKey := range newKeys {
		parsedKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(strKey))
		if err != nil {
			return err
		}
		srv.allowedKeys = append(srv.allowedKeys, parsedKey)
	}

	return nil
}

func NewSSHServer() (*Server, error) {
	ln, err := net.Listen("tcp", ":2222")
	if err != nil {
		return nil, err
	}
	return &Server{listener: ln, mu: sync.Mutex{}}, nil
}

// Stop stops SSH server. Blocking
func (srv *Server) Stop() error {
	err := srv.listener.Close()
	if err != nil {
		return err
	}
	return nil
}

// Start starts SSH server. Blocking
func (srv *Server) Start() error {
	handler := func(s ssh.Session) {
		authorizedKey := gossh.MarshalAuthorizedKey(s.PublicKey())
		io.WriteString(s, fmt.Sprintf("public key used by %s:\n", s.User()))
		s.Write(authorizedKey)
	}

	publicKeyOption := ssh.PublicKeyAuth(func(ctx ssh.Context, key ssh.PublicKey) bool {
		srv.mu.Lock()
		defer srv.mu.Unlock()

		for _, allowed := range srv.allowedKeys {
			if ssh.KeysEqual(allowed, key) {
				return true
			}
		}

		return false
	})

	err := ssh.Serve(srv.listener, handler, publicKeyOption)
	if err != nil {
		return err
	}

	return nil
}

func main() {

	server, err := NewSSHServer()
	if err != nil {
		return
	}

	err = server.UpdateKeys([]string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIwAoefixS03tYDfNuFfNRMO2syYfkw/C/76m8LS8xum"})
	if err != nil {
		return
	}

	err = server.Start()
	if err != nil {
		// will throw error when Stop has been called
	}
}

// generatePrivateKey creates RSA Private Key of specified byte size
func generatePrivateKey(bitSize int) (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return nil, err
	}

	err = privateKey.Validate()
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

// generatePublicKey takes a rsa.PublicKey and return bytes suitable for writing to .pub file
// returns the key in format format "ssh-rsa ..."
func generatePublicKey(privateKey *rsa.PublicKey) ([]byte, error) {
	publicRsaKey, err := gossh.NewPublicKey(privateKey)
	if err != nil {
		return nil, err
	}
	return gossh.MarshalAuthorizedKey(publicRsaKey), nil
}
