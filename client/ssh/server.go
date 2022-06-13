package ssh

import (
	"fmt"
	"github.com/creack/pty"
	"github.com/gliderlabs/ssh"
	log "github.com/sirupsen/logrus"
	"io"
	"net"
	"os"
	"os/exec"
	"sync"
)

var shell string

func init() {
	shell = os.Getenv("SHELL")
	if shell == "" {
		shell = "sh"
	}
}

type Srv interface {
}

// Server is the embedded NetBird SSH server
type Server struct {
	listener net.Listener
	// authorizedKeys is ssh pub key indexed by peer WireGuard public key
	authorizedKeys map[string]ssh.PublicKey
	mu             sync.Mutex
	hostKeyPEM     []byte
}

// NewSSHServer creates new server with provided host key
func NewSSHServer(hostKeyPEM []byte, addr string) (*Server, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	allowedKeys := make(map[string]ssh.PublicKey)
	return &Server{listener: ln, mu: sync.Mutex{}, hostKeyPEM: hostKeyPEM, authorizedKeys: allowedKeys}, nil
}

// RemoveAuthorizedKey removes SSH key of a given peer from the authorized keys
func (srv *Server) RemoveAuthorizedKey(peer string) {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	delete(srv.authorizedKeys, peer)
}

// AddAuthorizedKey add a given peer key to server authorized keys
func (srv *Server) AddAuthorizedKey(peer, newKey string) error {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	parsedKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(newKey))
	if err != nil {
		return err
	}

	srv.authorizedKeys[peer] = parsedKey
	return nil
}

// Stop stops SSH server.
func (srv *Server) Stop() error {
	err := srv.listener.Close()
	if err != nil {
		return err
	}
	return nil
}

func (srv *Server) publicKeyHandler(ctx ssh.Context, key ssh.PublicKey) bool {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	for _, allowed := range srv.authorizedKeys {
		if ssh.KeysEqual(allowed, key) {
			return true
		}
	}

	return false
}

// sessionHandler handles SSH session post auth
func (srv *Server) sessionHandler(s ssh.Session) {
	ptyReq, winCh, isPty := s.Pty()
	if isPty {
		cmd := exec.Command(shell)
		cmd.Env = append(cmd.Env, fmt.Sprintf("TERM=%s", ptyReq.Term))
		f, err := pty.Start(cmd)
		if err != nil {
			panic(err)
		}
		go func() {
			for win := range winCh {
				setWinSize(f, win.Width, win.Height)
			}
		}()

		srv.stdInOut(f, s)

		err = cmd.Wait()
		if err != nil {
			return
		}
	} else {
		_, err := io.WriteString(s, "only PTY is supported.\n")
		if err != nil {
			return
		}
		err = s.Exit(1)
		if err != nil {
			return
		}
	}
}

func (srv *Server) stdInOut(f *os.File, s ssh.Session) {
	go func() {
		// stdin
		_, err := io.Copy(f, s)
		if err != nil {
			return
		}
	}()

	go func() {
		// stdout
		_, err := io.Copy(s, f)
		if err != nil {
			return
		}
	}()
}

// Start starts SSH server. Blocking
func (srv *Server) Start() error {
	log.Infof("starting SSH server")

	publicKeyOption := ssh.PublicKeyAuth(srv.publicKeyHandler)
	hostKeyPEM := ssh.HostKeyPEM(srv.hostKeyPEM)

	err := ssh.Serve(srv.listener, srv.sessionHandler, publicKeyOption, hostKeyPEM)
	if err != nil {
		return err
	}

	return nil
}
