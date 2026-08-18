package ssh

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

// Handshake runs the SSH client handshake on an already dialed conn and
// returns the resulting client. Dialing bounds only the TCP establishment;
// without a deadline on the socket a peer that accepts and then goes silent
// blocks the handshake forever, so the context deadline is applied to conn
// for the duration of the handshake. conn is closed on any error.
func Handshake(ctx context.Context, conn net.Conn, addr string, config *ssh.ClientConfig) (*ssh.Client, error) {
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			closeHandshake(conn, "conn after deadline error")
			return nil, fmt.Errorf("set handshake deadline: %w", err)
		}
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
	if err != nil {
		closeHandshake(conn, "conn after handshake error")
		return nil, fmt.Errorf("ssh handshake: %w", err)
	}

	if err := conn.SetDeadline(time.Time{}); err != nil {
		closeHandshake(sshConn, "ssh conn after deadline clear error")
		return nil, fmt.Errorf("clear handshake deadline: %w", err)
	}

	return ssh.NewClient(sshConn, chans, reqs), nil
}

func closeHandshake(c io.Closer, label string) {
	if err := c.Close(); err != nil {
		log.Debugf("ssh: close %s: %v", label, err)
	}
}
