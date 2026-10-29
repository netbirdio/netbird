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

// preparedMsg contains the marshalled success response message for every supported protocol version
type preparedMsg struct {
	responseAuthMsg map[messages.ProtocolVersion][]byte
}

type handshake struct {
	conn        listener.Conn
	validator   Validator
	preparedMsg *preparedMsg

	peerID            *messages.PeerID
	advertisedVersion messages.ProtocolVersion
	selectedVersion   messages.ProtocolVersion
}

func newPreparedMsg(instanceURL string) (*preparedMsg, error) {
	responses := make(map[messages.ProtocolVersion][]byte, messages.CurrentProtocolVersion)
	for version := messages.ProtocolV1; ; version++ {
		ram, err := messages.NewEncoder(version).AuthResponse(instanceURL)
		if err != nil {
			return nil, fmt.Errorf("marshal auth response for version %d: %w", version, err)
		}
		responses[version] = ram
		if version == messages.CurrentProtocolVersion {
			break
		}
	}

	return &preparedMsg{
		responseAuthMsg: responses,
	}, nil
}

func (p *preparedMsg) authResponse(version messages.ProtocolVersion) ([]byte, error) {
	msg, ok := p.responseAuthMsg[version]
	if !ok {
		return nil, fmt.Errorf("no prepared auth response for protocol version %d", version)
	}
	return msg, nil
}

func (h *handshake) handshakeReceive(ctx context.Context) (*messages.PeerID, error) {
	buf := make([]byte, messages.MaxHandshakeSize)
	n, err := h.conn.Read(ctx, buf)
	if err != nil {
		return nil, fmt.Errorf("read from %s: %w", h.conn.RemoteAddr(), err)
	}

	buf = buf[:n]

	advertised, err := messages.ReadVersion(buf)
	if err != nil {
		return nil, fmt.Errorf("read version from %s: %w", h.conn.RemoteAddr(), err)
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
	h.advertisedVersion = advertised
	h.selectedVersion = messages.SelectVersion(advertised, messages.CurrentProtocolVersion)
	return peerID, nil
}

func (h *handshake) handshakeResponse(ctx context.Context) error {
	msg, err := h.preparedMsg.authResponse(h.selectedVersion)
	if err != nil {
		return err
	}

	if _, err := h.conn.Write(ctx, msg); err != nil {
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
