package server

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/netbirdio/netbird/relay/server/listener"
	"github.com/netbirdio/netbird/shared/peerauth"
	"github.com/netbirdio/netbird/shared/relay/messages"
)

const (
	// handshakeTimeout bounds how long a connection may remain in the
	// pre-authentication handshake phase before being closed.
	handshakeTimeout = 10 * time.Second

	// supportedProtocolVersion is the highest protocol version this relay accepts. It is above
	// messages.CurrentProtocolVersion, which clients advertise when they hold no bound token.
	supportedProtocolVersion = messages.ProtocolV2
)

var (
	errPeerAuthRequired      = errors.New("a token bound to the peer keys is required")
	errPeerAuthNotConfigured = errors.New("bound token presented but no Management public key is configured, set --peer-auth-public-keys")
	errPeerIDMismatch        = errors.New("peer ID does not match the token")
	errInvalidCredentials    = errors.New("invalid peer auth credentials")
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
	verifier    *peerauth.Verifier
	required    bool
	preparedMsg *preparedMsg

	peerID            *messages.PeerID
	advertisedVersion messages.ProtocolVersion
	selectedVersion   messages.ProtocolVersion
	authenticated     bool
}

func newPreparedMsg(instanceURL string) (*preparedMsg, error) {
	responses := make(map[messages.ProtocolVersion][]byte, supportedProtocolVersion)
	for version := messages.ProtocolV1; ; version++ {
		ram, err := messages.NewEncoder(version).AuthResponse(instanceURL)
		if err != nil {
			return nil, fmt.Errorf("marshal auth response for version %d: %w", version, err)
		}
		responses[version] = ram
		if version == supportedProtocolVersion {
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
	h.selectedVersion = messages.SelectVersion(advertised, supportedProtocolVersion)
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
	rawPeerID, token, err := messages.UnmarshalAuthMsg(buf)
	if err != nil {
		return nil, fmt.Errorf("unmarshal auth message: %w", err)
	}
	ext, err := messages.UnmarshalAuthExtension(buf)
	if err != nil {
		return rawPeerID, fmt.Errorf("unmarshal auth extension of %s (%s): %w", rawPeerID, h.conn.RemoteAddr(), err)
	}

	proof, err := peerauth.UnmarshalRelayExtension(ext)
	switch {
	case errors.Is(err, peerauth.ErrNoProof):
		return rawPeerID, h.validateLegacy(rawPeerID, token)
	case err != nil:
		return rawPeerID, fmt.Errorf("auth extension of %s (%s): %w: %w", rawPeerID, h.conn.RemoteAddr(), errInvalidCredentials, err)
	}

	if h.verifier == nil {
		return rawPeerID, fmt.Errorf("%s (%s): %w", rawPeerID, h.conn.RemoteAddr(), errPeerAuthNotConfigured)
	}
	if err := h.verifyBoundToken(*rawPeerID, token, proof); err != nil {
		return rawPeerID, fmt.Errorf("verify %s (%s): %w: %w", rawPeerID, h.conn.RemoteAddr(), errInvalidCredentials, err)
	}
	h.authenticated = true
	return rawPeerID, nil
}

func (h *handshake) validateLegacy(peerID *messages.PeerID, token []byte) error {
	if h.required {
		return fmt.Errorf("%s (%s): %w", peerID, h.conn.RemoteAddr(), errPeerAuthRequired)
	}
	if err := h.validator.Validate(token); err != nil {
		return fmt.Errorf("validate %s (%s): %w", peerID, h.conn.RemoteAddr(), err)
	}
	return nil
}

// verifyBoundToken checks the token and its proof, and that the peer ID it claims is the one of
// the WireGuard key the token is bound to.
func (h *handshake) verifyBoundToken(peerID messages.PeerID, token []byte, proof peerauth.Proof) error {
	t, err := h.verifier.Verify(token, proof, time.Now())
	if err != nil {
		return err
	}
	if messages.HashID(t.WGPub.String()) != peerID {
		return errPeerIDMismatch
	}
	return nil
}
