package server

import (
	"context"
	"fmt"
	"time"

	"github.com/netbirdio/netbird/relay/server/listener"
	"github.com/netbirdio/netbird/shared/relay/messages"
)

const (
	// handshakeTimeout bounds how long a connection may remain in the
	// pre-authentication handshake phase before being closed.
	handshakeTimeout = 10 * time.Second
)

type Validator interface {
	Validate(any) error
}

// preparedMsg contains the marshalled success response message
type preparedMsg struct {
	responseAuthMsg []byte
}

func newPreparedMsg(instanceURL string) (*preparedMsg, error) {
	ram, err := messages.MarshalAuthResponse(instanceURL)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal auth response msg: %w", err)
	}

	return &preparedMsg{
		responseAuthMsg: ram,
	}, nil
}

type handshake struct {
	conn        listener.Conn
	validator   Validator
	preparedMsg *preparedMsg

	peerID *messages.PeerID
}

func (h *handshake) handshakeReceive(ctx context.Context) (*messages.PeerID, error) {
	buf := make([]byte, messages.MaxHandshakeSize)
	n, err := h.conn.Read(ctx, buf)
	if err != nil {
		return nil, fmt.Errorf("read from %s: %w", h.conn.RemoteAddr(), err)
	}

	buf = buf[:n]

	_, err = messages.ValidateVersion(buf)
	if err != nil {
		return nil, fmt.Errorf("validate version from %s: %w", h.conn.RemoteAddr(), err)
	}

	msgType, err := messages.DetermineClientMessageType(buf)
	if err != nil {
		return nil, fmt.Errorf("determine message type from %s: %w", h.conn.RemoteAddr(), err)
	}

	if msgType != messages.MsgTypeAuth {
		return nil, fmt.Errorf("invalid message type %d from %s", msgType, h.conn.RemoteAddr())
	}

	peerID, err := h.handleAuthMsg(buf)
	if err != nil {
		return peerID, err
	}
	h.peerID = peerID
	return peerID, nil
}

func (h *handshake) handshakeResponse(ctx context.Context) error {
	if _, err := h.conn.Write(ctx, h.preparedMsg.responseAuthMsg); err != nil {
		return fmt.Errorf("handshake response write to %s (%s): %w", h.peerID, h.conn.RemoteAddr(), err)
	}

	return nil
}

func (h *handshake) handleAuthMsg(buf []byte) (*messages.PeerID, error) {
	rawPeerID, authPayload, err := messages.UnmarshalAuthMsg(buf)
	if err != nil {
		return nil, fmt.Errorf("unmarshal auth message: %w", err)
	}

	if err := h.validator.Validate(authPayload); err != nil {
		return rawPeerID, fmt.Errorf("validate %s (%s): %w", rawPeerID.String(), h.conn.RemoteAddr(), err)
	}

	return rawPeerID, nil
}
