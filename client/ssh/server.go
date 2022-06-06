package ssh

import (
	"fmt"
	"github.com/creack/pty"
	"github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
)

const DefaultShell = "sh"

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

/*func setWinSize(f *os.File, w, h int) {
	syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(syscall.TIOCSWINSZ),
		uintptr(unsafe.Pointer(&struct{ h, w, x, y uint16 }{uint16(h), uint16(w), 0, 0})))
}*/

// Start starts SSH server. Blocking
func (srv *Server) Start() error {
	handler := func(s ssh.Session) {
		var shell string
		shell = os.Getenv("SHELL")
		if shell == "" {
			shell = DefaultShell
		}
		cmd := exec.Command(shell)
		//cmd.Env = []string{"TERM=xterm"}
		ptyReq, _, isPty := s.Pty()
		if isPty {
			cmd.Env = append(cmd.Env, fmt.Sprintf("TERM=%s", ptyReq.Term))
			f, err := pty.Start(cmd)
			if err != nil {
				panic(err)
			}
			/*go func() {
				for win := range winCh {
					setWinSize(f, win.Width, win.Height)
				}
			}()*/
			go func() {
				io.Copy(f, s) // stdin
			}()
			io.Copy(s, f) // stdout
			cmd.Wait()
		} else {
			io.WriteString(s, "No PTY requested.\n")
			s.Exit(1)
		}
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
