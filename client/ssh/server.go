package ssh

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/creack/pty"
	"github.com/gliderlabs/ssh"
	log "github.com/sirupsen/logrus"
)

// DefaultSSHPort is the default SSH port of the NetBird's embedded SSH server
const DefaultSSHPort = 44338

// TerminalTimeout is the timeout for terminal session to be ready
const TerminalTimeout = 10 * time.Second

// TerminalBackoffDelay is the delay between terminal session readiness checks
const TerminalBackoffDelay = 500 * time.Millisecond

// DefaultSSHServer is a function that creates DefaultServer
func DefaultSSHServer(hostKeyPEM []byte, addr string) (Server, error) {
	return newDefaultServer(hostKeyPEM, addr)
}

// Server is an interface of SSH server
type Server interface {
	// Stop stops SSH server.
	Stop() error
	// Start starts SSH server. Blocking
	Start() error
	// RemoveAuthorizedKey removes SSH key of a given peer from the authorized keys
	RemoveAuthorizedKey(peer string)
	// AddAuthorizedKey add a given peer key to server authorized keys
	AddAuthorizedKey(peer, newKey string) error
}

// DefaultServer is the embedded NetBird SSH server
type DefaultServer struct {
	listener net.Listener
	// authorizedKeys is ssh pub key indexed by peer WireGuard public key
	authorizedKeys map[string]ssh.PublicKey
	mu             sync.Mutex
	hostKeyPEM     []byte
	sessions       []ssh.Session
}

// newDefaultServer creates new server with provided host key
func newDefaultServer(hostKeyPEM []byte, addr string) (*DefaultServer, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	allowedKeys := make(map[string]ssh.PublicKey)
	return &DefaultServer{listener: ln, mu: sync.Mutex{}, hostKeyPEM: hostKeyPEM, authorizedKeys: allowedKeys, sessions: make([]ssh.Session, 0)}, nil
}

// RemoveAuthorizedKey removes SSH key of a given peer from the authorized keys
func (srv *DefaultServer) RemoveAuthorizedKey(peer string) {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	delete(srv.authorizedKeys, peer)
}

// AddAuthorizedKey add a given peer key to server authorized keys
func (srv *DefaultServer) AddAuthorizedKey(peer, newKey string) error {
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
func (srv *DefaultServer) Stop() error {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	err := srv.listener.Close()
	if err != nil {
		return err
	}
	for _, session := range srv.sessions {
		err := session.Close()
		if err != nil {
			log.Warnf("failed closing SSH session from %v", err)
		}
	}

	return nil
}

func (srv *DefaultServer) publicKeyHandler(ctx ssh.Context, key ssh.PublicKey) bool {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	for _, allowed := range srv.authorizedKeys {
		if ssh.KeysEqual(allowed, key) {
			return true
		}
	}

	return false
}

func prepareUserEnv(user *user.User, shell string) []string {
	return []string{
		fmt.Sprintf("SHELL=" + shell),
		fmt.Sprintf("USER=" + user.Username),
		fmt.Sprintf("HOME=" + user.HomeDir),
	}
}

func acceptEnv(s string) bool {
	split := strings.Split(s, "=")
	if len(split) != 2 {
		return false
	}
	return split[0] == "TERM" || split[0] == "LANG" || strings.HasPrefix(split[0], "LC_")
}

// sessionHandler handles SSH session post auth
func (srv *DefaultServer) sessionHandler(session ssh.Session) {
	srv.mu.Lock()
	srv.sessions = append(srv.sessions, session)
	srv.mu.Unlock()

	defer func() {
		err := session.Close()
		if err != nil {
			return
		}
	}()

	log.Infof("Establishing SSH session for %s from host %s", session.User(), session.RemoteAddr().String())

	localUser, err := userNameLookup(session.User())
	if err != nil {
		_, err = fmt.Fprintf(session, "remote SSH server couldn't find local user %s\n", session.User()) //nolint
		err = session.Exit(1)
		if err != nil {
			return
		}
		log.Warnf("failed SSH session from %v, user %s", session.RemoteAddr(), session.User())
		return
	}

	ptyReq, winCh, isPty := session.Pty()
	if isPty {
		loginCmd, loginArgs, err := getLoginCmd(localUser.Username, session.RemoteAddr())
		if err != nil {
			log.Warnf("failed logging-in user %s from remote IP %s", localUser.Username, session.RemoteAddr().String())
			return
		}
		cmd := exec.Command(loginCmd, loginArgs...)
		go func() {
			<-session.Context().Done()
			err := cmd.Process.Kill()
			if err != nil {
				return
			}
		}()
		cmd.Dir = localUser.HomeDir
		cmd.Env = append(cmd.Env, fmt.Sprintf("TERM=%s", ptyReq.Term))
		cmd.Env = append(cmd.Env, prepareUserEnv(localUser, getUserShell(localUser.Uid))...)
		for _, v := range session.Environ() {
			if acceptEnv(v) {
				cmd.Env = append(cmd.Env, v)
			}
		}

		log.Debugf("Login command: %s", cmd.String())
		file, err := pty.Start(cmd)
		if err != nil {
			log.Errorf("failed starting SSH server %v", err)
		}

		go func() {
			for win := range winCh {
				setWinSize(file, win.Width, win.Height)
			}
		}()

		srv.stdInOut(file, session)

		err = cmd.Wait()
		if err != nil {
			return
		}
	} else {
		_, err := io.WriteString(session, "only PTY is supported.\n")
		if err != nil {
			return
		}
		err = session.Exit(1)
		if err != nil {
			return
		}
	}
	log.Debugf("SSH session ended")
}

func (srv *DefaultServer) stdInOut(file *os.File, session ssh.Session) {
	go func() {
		// stdin
		_, err := io.Copy(file, session)
		if err != nil {
			_ = session.Exit(1)
			return
		}
	}()

	// AWS Linux 2 machines need some time to open the terminal so we need to wait for it
	timer := time.NewTimer(TerminalTimeout)
	for {
		select {
		case <-timer.C:
			_, _ = session.Write([]byte("Reached timeout while opening connection\n"))
			_ = session.Exit(1)
			return
		default:
			// stdout
			writtenBytes, err := io.Copy(session, file)
			if err != nil && writtenBytes != 0 {
				_ = session.Exit(0)
				return
			}
			time.Sleep(TerminalBackoffDelay)
		}
	}
}

// Start starts SSH server. Blocking
func (srv *DefaultServer) Start() error {
	log.Infof("starting SSH server on addr: %s", srv.listener.Addr().String())

	publicKeyOption := ssh.PublicKeyAuth(srv.publicKeyHandler)
	hostKeyPEM := ssh.HostKeyPEM(srv.hostKeyPEM)
	err := ssh.Serve(srv.listener, srv.sessionHandler, publicKeyOption, hostKeyPEM)
	if err != nil {
		return err
	}

	return nil
}

func getUserShell(userID string) string {
	if runtime.GOOS == "linux" {
		output, _ := exec.Command("getent", "passwd", userID).Output()
		line := strings.SplitN(string(output), ":", 10)
		if len(line) > 6 {
			return strings.TrimSpace(line[6])
		}
	}

	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/sh"
	}
	return shell
}
