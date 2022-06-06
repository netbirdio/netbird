package ssh

import (
	"fmt"
	"github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"
	"io"
	"net"
	"strings"
	"sync"
)

type Server struct {
	listener    net.Listener
	allowedKeys map[string]ssh.PublicKey
	mu          sync.Mutex
	hostKeyPEM  []byte
}

// NewSSHServer creates new server with provided host key
func NewSSHServer(hostKeyPEM []byte, addr string) (*Server, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	allowedKeys := make(map[string]ssh.PublicKey)
	return &Server{listener: ln, mu: sync.Mutex{}, hostKeyPEM: hostKeyPEM, allowedKeys: allowedKeys}, nil
}

// AddAuthorizedKey add given key as authorized key to the server
func (srv *Server) AddAuthorizedKey(newKey string) error {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	parsedKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(newKey))
	if err != nil {
		return err
	}
	strKey := strings.TrimSpace(string(gossh.MarshalAuthorizedKey(parsedKey)))
	srv.allowedKeys[strKey] = parsedKey
	return nil
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

		k := strings.TrimSpace(string(gossh.MarshalAuthorizedKey(key)))
		if allowed, ok := srv.allowedKeys[k]; ok {
			if ssh.KeysEqual(allowed, key) {
				return true
			}
		}

		return false
	})

	hostKeyPEM := ssh.HostKeyPEM(srv.hostKeyPEM)

	err := ssh.Serve(srv.listener, handler, publicKeyOption, hostKeyPEM)
	if err != nil {
		return err
	}

	return nil
}
