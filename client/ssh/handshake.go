package ssh

import (
	"context"
	"fmt"
	"io"
	"net"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

// Handshake runs the SSH client handshake on an already dialed conn and
// returns the resulting client. Dialing bounds only the TCP establishment;
// a peer that accepts and then goes silent would block the handshake forever,
// so conn is closed as soon as ctx is done, which unblocks the handshake and
// surfaces the context error. conn is closed on any error.
func Handshake(ctx context.Context, conn net.Conn, addr string, config *ssh.ClientConfig) (*ssh.Client, error) {
	stop := context.AfterFunc(ctx, func() { closeHandshake(conn, "conn on context done") })

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
	if err != nil {
		if stop() {
			closeHandshake(conn, "conn after handshake error")
		}
		return nil, handshakeError(ctx, err)
	}

	if !stop() {
		closeHandshake(sshConn, "ssh conn after context done")
		return nil, fmt.Errorf("ssh handshake: %w", ctx.Err())
	}

	return ssh.NewClient(sshConn, chans, reqs), nil
}

func closeHandshake(c io.Closer, label string) {
	if err := c.Close(); err != nil {
		log.Debugf("ssh: close %s: %v", label, err)
	}
}

func handshakeError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return fmt.Errorf("ssh handshake: %w: %w", ctxErr, err)
	}
	return fmt.Errorf("ssh handshake: %w", err)
}
