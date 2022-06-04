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
func NewSSHServer(hostKeyPEM []byte) (*Server, error) {
	ln, err := net.Listen("tcp", ":2222")
	if err != nil {
		return nil, err
	}
	return &Server{listener: ln, mu: sync.Mutex{}, hostKeyPEM: hostKeyPEM}, nil
}

func (srv *Server) UpdateKeys(newKeys []string) error {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	srv.allowedKeys = make(map[string]ssh.PublicKey, len(newKeys))
	for _, strKey := range newKeys {
		parsedKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(strKey))
		if err != nil {
			return err
		}
		srv.allowedKeys[strKey] = parsedKey
	}

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

func main() {

	strKey := "-----BEGIN RSA PRIVATE KEY-----\n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\n-----END RSA PRIVATE KEY-----\n"
	server, err := NewSSHServer([]byte(strKey))
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
