package server

import (
	"fmt"
	"net"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/shared/relay/messages"
	//nolint:staticcheck
	"github.com/netbirdio/netbird/shared/relay/messages/address"
	//nolint:staticcheck
	authmsg "github.com/netbirdio/netbird/shared/relay/messages/auth"
)

type Validator interface {
	Validate(any) error
	// Deprecated: Use Validate instead.
	ValidateHelloMsgType(any) error
}

// preparedMsg contains the marshalled success response messages
type preparedMsg struct {
	responseHelloMsg []byte
	responseAuthMsg  []byte
}

func newPreparedMsg(instanceURL string) (*preparedMsg, error) {
	rhm, err := marshalResponseHelloMsg(instanceURL)
	if err != nil {
		return nil, err
	}

	ram, err := messages.MarshalAuthResponse(instanceURL)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal auth response msg: %w", err)
	}

	return &preparedMsg{
		responseHelloMsg: rhm,
		responseAuthMsg:  ram,
	}, nil
}

func marshalResponseHelloMsg(instanceURL string) ([]byte, error) {
	addr := &address.Address{URL: instanceURL}
	addrData, err := addr.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response address: %w", err)
	}

	//nolint:staticcheck
	responseMsg, err := messages.MarshalHelloResponse(addrData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal hello response: %w", err)
	}
	return responseMsg, nil
}

type handshake struct {
	conn        net.Conn
	validator   Validator
	preparedMsg *preparedMsg

	handshakeMethodAuth bool
	peerID              *messages.PeerID
}

func (h *handshake) handshakeReceive() (*messages.PeerID, error) {
	buf := make([]byte, messages.MaxHandshakeSize)
	n, err := h.conn.Read(buf)
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

	var peerID *messages.PeerID
	switch msgType {
	//nolint:staticcheck
	case messages.MsgTypeHello:
		peerID, err = h.handleHelloMsg(buf)
	case messages.MsgTypeAuth:
		h.handshakeMethodAuth = true
		peerID, err = h.handleAuthMsg(buf)
	default:
		return nil, fmt.Errorf("invalid message type %d from %s", msgType, h.conn.RemoteAddr())
	}
	if err != nil {
		return peerID, err
	}
	h.peerID = peerID
	return peerID, nil
}

func (h *handshake) handshakeResponse() error {
	var responseMsg []byte
	if h.handshakeMethodAuth {
		responseMsg = h.preparedMsg.responseAuthMsg
	} else {
		responseMsg = h.preparedMsg.responseHelloMsg
	}

	if _, err := h.conn.Write(responseMsg); err != nil {
		return fmt.Errorf("handshake response write to %s (%s): %w", h.peerID, h.conn.RemoteAddr(), err)
	}

	return nil
}

func (h *handshake) handleHelloMsg(buf []byte) (*messages.PeerID, error) {
	//nolint:staticcheck
	peerID, authData, err := messages.UnmarshalHelloMsg(buf)
	if err != nil {
		return nil, fmt.Errorf("unmarshal hello message: %w", err)
	}

	log.Warnf("peer %s (%s) is using deprecated initial message type", peerID, h.conn.RemoteAddr())

	authMsg, err := authmsg.UnmarshalMsg(authData)
	if err != nil {
		return nil, fmt.Errorf("unmarshal auth message: %w", err)
	}

	//nolint:staticcheck
	if err := h.validator.ValidateHelloMsgType(authMsg.AdditionalData); err != nil {
		return nil, fmt.Errorf("validate %s (%s): %w", peerID, h.conn.RemoteAddr(), err)
	}

	return peerID, nil
}

func (h *handshake) handleAuthMsg(buf []byte) (*messages.PeerID, error) {
	rawPeerID, authPayload, err := messages.UnmarshalAuthMsg(buf)
	if err != nil {
		return nil, fmt.Errorf("unmarshal hello message: %w", err)
	}

	if err := h.validator.Validate(authPayload); err != nil {
		return rawPeerID, fmt.Errorf("validate %s (%s): %w", rawPeerID.String(), h.conn.RemoteAddr(), err)
	}

	return rawPeerID, nil
}
