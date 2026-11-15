package server

import (
	"context"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/relay/server/listener"
	"github.com/netbirdio/netbird/shared/alignedhb"
	"github.com/netbirdio/netbird/shared/alignedhb/hbmetrics"
	"github.com/netbirdio/netbird/shared/alignedhb/phasectl"
	"github.com/netbirdio/netbird/shared/alignedhb/phasesig"
	"github.com/netbirdio/netbird/shared/relay/healthcheck"
	"github.com/netbirdio/netbird/shared/relay/messages"
)

const (
	// handshakeTimeout bounds how long a connection may remain in the
	// pre-authentication handshake phase before being closed.
	handshakeTimeout = 10 * time.Second

	// maxProtocolVersion is the highest protocol version this server selects.
	// Version 2 turns the aligned heartbeat on for clients that offer it.
	maxProtocolVersion = messages.ProtocolV2
)

type Validator interface {
	Validate(any) error
}

// preparedMsg contains the marshalled success response message for every supported protocol version
type preparedMsg struct {
	responseAuthMsg map[messages.ProtocolVersion][]byte
}

type handshake struct {
	conn          listener.Conn
	validator     Validator
	phaseVerifier *phasesig.Verifier
	periodLimits  alignedhb.PeriodLimits
	hbMetrics     *hbmetrics.Metrics
	preparedMsg   *preparedMsg

	peerID            *messages.PeerID
	advertisedVersion messages.ProtocolVersion
	selectedVersion   messages.ProtocolVersion
	// aligned is set when the selected version turns the aligned heartbeat on.
	aligned *verifiedPhase
}

// verifiedPhase is a signed phase the relay verified: the schedule it sets and
// the day it was signed for.
type verifiedPhase struct {
	schedule healthcheck.AlignedSchedule
	day      int64
}

func newPreparedMsg(instanceURL string) (*preparedMsg, error) {
	responses := make(map[messages.ProtocolVersion][]byte, maxProtocolVersion)
	for version := messages.ProtocolV1; ; version++ {
		ram, err := messages.NewEncoder(version, messages.MaxMessageSize).AuthResponse(instanceURL)
		if err != nil {
			return nil, fmt.Errorf("marshal auth response for version %d: %w", version, err)
		}
		responses[version] = ram
		if version == maxProtocolVersion {
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

	selected := messages.SelectVersion(advertised, maxProtocolVersion)
	var aligned *verifiedPhase
	if selected >= messages.ProtocolV2 {
		aligned = alignedSchedule(buf, *peerID, h.phaseVerifier, h.periodLimits, h.hbMetrics, time.Now())
	}

	h.peerID = peerID
	h.advertisedVersion = advertised
	h.selectedVersion = selected
	h.aligned = aligned
	return peerID, nil
}

// alignedSchedule reads the aligned heartbeat request from the auth extension
// area. It returns the verified phase when the client sent a phase Management signed
// for peerID, nil otherwise: the connection then keeps the stock health check.
// A malformed extension is ignored the same way, so a capability problem never
// cuts a client off.
func alignedSchedule(authMsg []byte, peerID messages.PeerID, verifier *phasesig.Verifier, limits alignedhb.PeriodLimits, m *hbmetrics.Metrics, now time.Time) *verifiedPhase {
	raw, err := messages.AuthMsgExtension(authMsg)
	if err != nil {
		log.Debugf("ignoring auth extension from %s, stock health check: %v", peerID, err)
		return nil
	}
	ext, err := messages.UnmarshalAuthExtension(raw)
	if err != nil {
		log.Debugf("ignoring auth extension from %s, stock health check: %v", peerID, err)
		return nil
	}
	return verifySignedPhase(ext, peerID, verifier, limits, m, now)
}

// verifySignedPhase returns the signed phase in ext, nil when ext has none or
// it is not a phase Management signed for peerID. The health check runs on the
// period phasectl.Verify clamped. m counts a phase that fails to verify.
func verifySignedPhase(ext messages.AuthExtension, peerID messages.PeerID, verifier *phasesig.Verifier, limits alignedhb.PeriodLimits, m *hbmetrics.Metrics, now time.Time) *verifiedPhase {
	if ext.SignedPhase == nil || ext.PeriodSeconds == 0 {
		return nil
	}
	if verifier == nil {
		log.Tracef("no phase verifier configured, stock health check for %s", peerID)
		return nil
	}
	requested := time.Duration(ext.PeriodSeconds) * time.Second
	signed := alignedhb.SignedPhase{
		Phase:     time.Duration(ext.SignedPhase.PhaseMs) * time.Millisecond,
		Day:       ext.SignedPhase.Day,
		Signature: ext.SignedPhase.Signature,
	}
	answer, err := phasectl.Verify(verifier, limits, peerID, requested, signed, now, m)
	if answer.Period != requested {
		log.Debugf("aligned heartbeat period %s from %s clamped to %s", requested, peerID, answer.Period)
	}
	if err != nil {
		log.Debugf("ignoring aligned heartbeat phase from %s: %v", peerID, err)
		return nil
	}
	return &verifiedPhase{schedule: healthcheck.AlignedSchedule(answer), day: signed.Day}
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
