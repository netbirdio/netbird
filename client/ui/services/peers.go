//go:build !android && !ios && !freebsd && !js

package services

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/client/ui/authsession"
	"github.com/netbirdio/netbird/client/ui/updater"
)

const (
	// EventStatus is emitted to the frontend whenever a fresh Status snapshot
	// is captured (from a poll or a stream-driven refresh).
	EventStatus = "netbird:status"
	// EventSystem is emitted for each SubscribeEvents message (DNS, network,
	// auth, connectivity categories). Auto-update SystemEvents are also
	// forwarded here to updater.Holder.OnSystemEvent so the typed update
	// state can be maintained without a second daemon subscription.
	EventSystem = "netbird:event"
	// EventProfileChanged fires after ProfileSwitcher.SwitchActive completes
	// a daemon-side switch. The payload is the new ProfileRef. Both tray
	// and React subscribers refresh their profile views off this so a flip
	// driven from one surface (tray menu, settings page) paints in the
	// others without polling. The daemon itself does not emit a profile
	// event, so this is the only signal that closes the gap.
	EventProfileChanged = "netbird:profile:changed"
	// EventSessionWarning is emitted on every session-warning watcher
	// fire (T-WarningLead and T-FinalWarningLead) as a strongly-typed
	// sibling of EventSystem so React / tray subscribers don't have to
	// filter the firehose of EventSystem. Consumers branch on the
	// SessionWarning.Final flag to tell the interactive T-10 event apart
	// from the fallback T-2 event; the dialog auto-open lives in the
	// tray (Go side) so the frontend stays passive on this flow.
	EventSessionWarning = "netbird:session:warning"

	// StatusDaemonUnavailable is the synthetic Status the UI emits when the
	// daemon's gRPC socket is unreachable (daemon not running, socket
	// permission, etc.). Real daemon statuses come straight from
	// internal.Status* — none of those collide with this label.
	StatusDaemonUnavailable = "DaemonUnavailable"

	// Daemon connection status strings — mirror internal.Status* in
	// client/internal/state.go.
	StatusConnected      = "Connected"
	StatusConnecting     = "Connecting"
	StatusIdle           = "Idle"
	StatusNeedsLogin     = "NeedsLogin"
	StatusLoginFailed    = "LoginFailed"
	StatusSessionExpired = "SessionExpired"
)

// Emitter is what peers.Watch needs from the host application: a simple
// "send this name and payload to the frontend" hook.  The Wails app.Event
// satisfies this with its Emit method.
type Emitter interface {
	Emit(name string, data ...any) bool
}

// SystemEvent is the frontend-facing shape of a daemon SystemEvent.
type SystemEvent struct {
	ID          string            `json:"id"`
	Severity    string            `json:"severity"`
	Category    string            `json:"category"`
	Message     string            `json:"message"`
	UserMessage string            `json:"userMessage"`
	Timestamp   int64             `json:"timestamp"`
	Metadata    map[string]string `json:"metadata"`
}

// PeerStatus is the frontend-facing shape of a daemon PeerState. Carries
// enough detail for the dashboard's compact peer row plus the on-click
// troubleshooting expansion (ICE candidate types, endpoints, handshake age).
type PeerStatus struct {
	IP                         string   `json:"ip"`
	PubKey                     string   `json:"pubKey"`
	ConnStatus                 string   `json:"connStatus"`
	ConnStatusUpdateUnix       int64    `json:"connStatusUpdateUnix"`
	Relayed                    bool     `json:"relayed"`
	LocalIceCandidateType      string   `json:"localIceCandidateType"`
	RemoteIceCandidateType     string   `json:"remoteIceCandidateType"`
	LocalIceCandidateEndpoint  string   `json:"localIceCandidateEndpoint"`
	RemoteIceCandidateEndpoint string   `json:"remoteIceCandidateEndpoint"`
	Fqdn                       string   `json:"fqdn"`
	BytesRx                    int64    `json:"bytesRx"`
	BytesTx                    int64    `json:"bytesTx"`
	LatencyMs                  int64    `json:"latencyMs"`
	RelayAddress               string   `json:"relayAddress"`
	LastHandshakeUnix          int64    `json:"lastHandshakeUnix"`
	RosenpassEnabled           bool     `json:"rosenpassEnabled"`
	Networks                   []string `json:"networks"`
}

// PeerLink is one of the named connections between this peer and its mgmt
// or signal server.
type PeerLink struct {
	URL       string `json:"url"`
	Connected bool   `json:"connected"`
	Error     string `json:"error,omitempty"`
}

// LocalPeer mirrors LocalPeerState — what this client looks like on the mesh.
type LocalPeer struct {
	IP       string   `json:"ip"`
	PubKey   string   `json:"pubKey"`
	Fqdn     string   `json:"fqdn"`
	Networks []string `json:"networks"`
}

// Status is the snapshot the frontend renders on the dashboard.
type Status struct {
	Status        string        `json:"status"`
	DaemonVersion string        `json:"daemonVersion"`
	Management    PeerLink      `json:"management"`
	Signal        PeerLink      `json:"signal"`
	Local         LocalPeer     `json:"local"`
	Peers         []PeerStatus  `json:"peers"`
	Events        []SystemEvent `json:"events"`
	// NetworksRevision bumps whenever the daemon's routed-networks set or their
	// selected state changes. Consumers fingerprint on it to know when to
	// re-fetch ListNetworks instead of polling every snapshot.
	NetworksRevision uint64 `json:"networksRevision"`
	// SessionExpiresAt is the absolute UTC instant at which the peer's
	// SSO session expires. nil when the peer is not SSO-tracked or login
	// expiration is disabled (either server-side off, or peer not
	// SSO-registered). The UI derives "warning active" from this value
	// plus its own clock.
	SessionExpiresAt *time.Time `json:"sessionExpiresAt,omitempty"`
}

// Peers serves the dashboard data: one polled Status RPC and a long-running
// SubscribeEvents stream that re-emits every event over the Wails event bus.
//
// Profile-switch suppression: ProfileSwitcher calls BeginProfileSwitch
// before tearing down the old profile when it would otherwise be followed
// by an Up on the new profile (i.e. previous status was Connected or
// Connecting). statusStreamLoop then swallows the transient stale
// Connected and Idle pushes the daemon emits during Down so the tray
// and the React Status page both see Connecting → new-profile-state
// instead of Connected → Connected → Idle → Connecting → new-state.
//
// Suppression transition (applied by shouldSuppress before each emit):
//
//	┌────────────────────────────────────────────┬──────────────────────────────────┐
//	│ Incoming daemon status                     │ Action                           │
//	├────────────────────────────────────────────┼──────────────────────────────────┤
//	│ Connected, Idle                            │ Suppress (the blink we hide)     │
//	│ Connecting                                 │ Emit, clear flag (new Up began)  │
//	│ NeedsLogin, LoginFailed, SessionExpired,   │ Emit, clear flag (new profile's  │
//	│   DaemonUnavailable                        │   "Up won't run" terminal state) │
//	│ (timeout elapsed)                          │ Clear flag, emit normally        │
//	└────────────────────────────────────────────┴──────────────────────────────────┘
type Peers struct {
	conn    DaemonConn
	emitter Emitter
	updater *updater.Holder

	mu       sync.Mutex
	cancel   context.CancelFunc
	streamWg sync.WaitGroup

	switchMu              sync.Mutex
	switchInProgress      bool
	switchInProgressUntil time.Time
}

func NewPeers(conn DaemonConn, emitter Emitter, updaterHolder *updater.Holder) *Peers {
	return &Peers{conn: conn, emitter: emitter, updater: updaterHolder}
}

// BeginProfileSwitch is called by ProfileSwitcher at the start of a switch
// when the previous status was Connected/Connecting — i.e. the daemon is
// about to emit Connected updates during Down's peer-count teardown and
// then an Idle before the new profile's Up resumes the stream. The flag
// makes statusStreamLoop drop those transient events. A synthetic
// Connecting snapshot is emitted right away so both consumers (tray and
// React) paint the optimistic state immediately. A 30s safety timeout
// clears the flag if the daemon never emits a follow-up status.
func (s *Peers) BeginProfileSwitch() {
	s.switchMu.Lock()
	s.switchInProgress = true
	s.switchInProgressUntil = time.Now().Add(30 * time.Second)
	s.switchMu.Unlock()
	s.emitter.Emit(EventStatus, Status{Status: StatusConnecting})
}

// CancelProfileSwitch is called by callers that abort the switch midway
// (the tray's Disconnect click while Connecting). Clears the suppression
// flag so the next daemon Idle paints through immediately instead of
// being swallowed.
func (s *Peers) CancelProfileSwitch() {
	s.switchMu.Lock()
	s.switchInProgress = false
	s.switchMu.Unlock()
}

func (s *Peers) shouldSuppress(st Status) bool {
	s.switchMu.Lock()
	defer s.switchMu.Unlock()
	if !s.switchInProgress {
		return false
	}
	if time.Now().After(s.switchInProgressUntil) {
		s.switchInProgress = false
		return false
	}
	switch {
	case strings.EqualFold(st.Status, StatusConnecting),
		strings.EqualFold(st.Status, StatusNeedsLogin),
		strings.EqualFold(st.Status, StatusLoginFailed),
		strings.EqualFold(st.Status, StatusSessionExpired),
		strings.EqualFold(st.Status, StatusDaemonUnavailable):
		// New profile's flow has officially begun (Up started, or daemon
		// refused to start it). Clear the guard and let it through.
		s.switchInProgress = false
		return false
	default:
		// Connected (stale carryover from old profile's teardown) or Idle
		// (transient between Down and Up). Suppress so the optimistic
		// Connecting from BeginProfileSwitch stays painted.
		return true
	}
}

// Watch starts the background loops that feed the frontend:
//   - statusStreamLoop: push-driven snapshots on connection-state change
//     (Connected/Disconnected/Connecting, peer list, address). Drives the
//     tray icon, Status page, and Peers page.
//   - toastStreamLoop:   DNS / network / auth / connectivity / update
//     SystemEvent stream. Drives OS notifications, the Recent Events
//     list, and the update-overlay flag. The daemon-side RPC is named
//     SubscribeEvents — only the loop's local alias differs to keep the
//     two streams distinguishable in this file.
//
// Safe to call once at boot; both loops self-restart on stream errors
// via exponential backoff.
func (s *Peers) Watch(ctx context.Context) {
	s.mu.Lock()
	if s.cancel != nil {
		s.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	s.mu.Unlock()

	s.streamWg.Add(2)
	go s.statusStreamLoop(ctx)
	go s.toastStreamLoop(ctx)
}

// ServiceShutdown is the Wails service hook fired on app exit.
func (s *Peers) ServiceShutdown() error {
	s.mu.Lock()
	cancel := s.cancel
	s.cancel = nil
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	s.streamWg.Wait()
	return nil
}

// Get returns the current daemon status snapshot. When the daemon socket
// is unreachable (process down, socket missing, permission denied) it
// returns Status{Status: StatusDaemonUnavailable} instead of an error so
// the frontend's initial useStatus().refresh() picks up the same string
// the live event stream emits — the React overlay and per-screen gating
// then key off a single status enum without a parallel "error" path.
func (s *Peers) Get(ctx context.Context) (Status, error) {
	cli, err := s.conn.Client()
	if err != nil {
		if isDaemonUnreachable(err) {
			return Status{Status: StatusDaemonUnavailable}, nil
		}
		return Status{}, err
	}
	resp, err := cli.Status(ctx, &proto.StatusRequest{GetFullPeerStatus: true})
	if err != nil {
		if isDaemonUnreachable(err) {
			return Status{Status: StatusDaemonUnavailable}, nil
		}
		return Status{}, err
	}
	return statusFromProto(resp), nil
}

// statusStreamLoop subscribes to the daemon's SubscribeStatus stream and
// re-emits each FullStatus snapshot on the Wails event bus. The first
// message is the current snapshot; subsequent messages fire on
// connection-state changes only — no fixed-interval polling, no idle
// chatter. Reconnects with exponential backoff if the stream drops
// (daemon restart, socket break).
func (s *Peers) statusStreamLoop(ctx context.Context) {
	defer s.streamWg.Done()

	bo := backoff.WithContext(&backoff.ExponentialBackOff{
		InitialInterval:     time.Second,
		RandomizationFactor: backoff.DefaultRandomizationFactor,
		Multiplier:          backoff.DefaultMultiplier,
		MaxInterval:         10 * time.Second,
		MaxElapsedTime:      0,
		Stop:                backoff.Stop,
		Clock:               backoff.SystemClock,
	}, ctx)

	// unavailable tracks whether we've already signalled the daemon as
	// unreachable. The synthetic event is emitted once per outage so the
	// tray flips to the "Daemon not running" state, but the exponential
	// backoff retries don't re-fire it on every attempt.
	unavailable := false
	emitUnavailable := func() {
		if unavailable {
			return
		}
		unavailable = true
		s.emitter.Emit(EventStatus, Status{Status: StatusDaemonUnavailable})
	}

	op := func() error {
		cli, err := s.conn.Client()
		if err != nil {
			emitUnavailable()
			return fmt.Errorf("get client: %w", err)
		}
		stream, err := cli.SubscribeStatus(ctx, &proto.StatusRequest{GetFullPeerStatus: true})
		if err != nil {
			if isDaemonUnreachable(err) {
				emitUnavailable()
			}
			return fmt.Errorf("subscribe status: %w", err)
		}
		for {
			resp, err := stream.Recv()
			if err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				if isDaemonUnreachable(err) {
					emitUnavailable()
				}
				return fmt.Errorf("status stream recv: %w", err)
			}
			unavailable = false
			st := statusFromProto(resp)
			log.Infof("backend event: status status=%q peers=%d", st.Status, len(st.Peers))
			if s.shouldSuppress(st) {
				log.Debugf("suppressing status=%q during profile switch", st.Status)
				continue
			}
			s.emitter.Emit(EventStatus, st)
		}
	}

	if err := backoff.Retry(op, bo); err != nil && ctx.Err() == nil {
		log.Errorf("status stream ended: %v", err)
	}
}

// toastStreamLoop subscribes to the daemon's SubscribeEvents RPC and
// re-emits every SystemEvent on the Wails event bus. The downstream
// consumers turn these into OS notifications, populate the Recent
// Events card on the Status page, and listen for the
// "new_version_available" metadata to flip the tray's update overlay.
// Local name differs from the RPC ("SubscribeEvents") so the file's
// two streams aren't both called streamLoop.
func (s *Peers) toastStreamLoop(ctx context.Context) {
	defer s.streamWg.Done()

	bo := backoff.WithContext(&backoff.ExponentialBackOff{
		InitialInterval:     time.Second,
		RandomizationFactor: backoff.DefaultRandomizationFactor,
		Multiplier:          backoff.DefaultMultiplier,
		MaxInterval:         10 * time.Second,
		MaxElapsedTime:      0,
		Stop:                backoff.Stop,
		Clock:               backoff.SystemClock,
	}, ctx)

	op := func() error {
		cli, err := s.conn.Client()
		if err != nil {
			return fmt.Errorf("get client: %w", err)
		}
		stream, err := cli.SubscribeEvents(ctx, &proto.SubscribeRequest{})
		if err != nil {
			return fmt.Errorf("subscribe: %w", err)
		}
		for {
			ev, err := stream.Recv()
			if err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				return fmt.Errorf("stream recv: %w", err)
			}
			se := systemEventFromProto(ev)
			log.Infof("backend event: system severity=%s category=%s msg=%q", se.Severity, se.Category, se.UserMessage)
			s.emitter.Emit(EventSystem, se)
			if warn, ok := authsession.WarningFromMetadata(se.Metadata); ok {
				s.emitter.Emit(EventSessionWarning, warn)
			}
			if s.updater != nil {
				s.updater.OnSystemEvent(ev)
			}
		}
	}

	if err := backoff.Retry(op, bo); err != nil && ctx.Err() == nil {
		log.Errorf("event stream ended: %v", err)
	}
}

func statusFromProto(resp *proto.StatusResponse) Status {
	full := resp.GetFullStatus()
	mgmt := full.GetManagementState()
	sig := full.GetSignalState()
	local := full.GetLocalPeerState()

	st := Status{
		Status:           resp.GetStatus(),
		DaemonVersion:    resp.GetDaemonVersion(),
		NetworksRevision: full.GetNetworksRevision(),
		Management: PeerLink{
			URL:       mgmt.GetURL(),
			Connected: mgmt.GetConnected(),
			Error:     mgmt.GetError(),
		},
		Signal: PeerLink{
			URL:       sig.GetURL(),
			Connected: sig.GetConnected(),
			Error:     sig.GetError(),
		},
		Local: LocalPeer{
			IP:       local.GetIP(),
			PubKey:   local.GetPubKey(),
			Fqdn:     local.GetFqdn(),
			Networks: append([]string{}, local.GetNetworks()...),
		},
	}

	for _, p := range full.GetPeers() {
		st.Peers = append(st.Peers, PeerStatus{
			IP:                         p.GetIP(),
			PubKey:                     p.GetPubKey(),
			ConnStatus:                 p.GetConnStatus(),
			ConnStatusUpdateUnix:       p.GetConnStatusUpdate().GetSeconds(),
			Relayed:                    p.GetRelayed(),
			LocalIceCandidateType:      p.GetLocalIceCandidateType(),
			RemoteIceCandidateType:     p.GetRemoteIceCandidateType(),
			LocalIceCandidateEndpoint:  p.GetLocalIceCandidateEndpoint(),
			RemoteIceCandidateEndpoint: p.GetRemoteIceCandidateEndpoint(),
			Fqdn:                       p.GetFqdn(),
			BytesRx:                    p.GetBytesRx(),
			BytesTx:                    p.GetBytesTx(),
			LatencyMs:                  p.GetLatency().AsDuration().Milliseconds(),
			RelayAddress:               p.GetRelayAddress(),
			LastHandshakeUnix:          p.GetLastWireguardHandshake().GetSeconds(),
			RosenpassEnabled:           p.GetRosenpassEnabled(),
			Networks:                   append([]string{}, p.GetNetworks()...),
		})
	}
	for _, e := range full.GetEvents() {
		st.Events = append(st.Events, systemEventFromProto(e))
	}
	if ts := resp.GetSessionExpiresAt(); ts.IsValid() && !ts.AsTime().IsZero() {
		t := ts.AsTime().UTC()
		st.SessionExpiresAt = &t
	}
	return st
}

func systemEventFromProto(e *proto.SystemEvent) SystemEvent {
	out := SystemEvent{
		ID:          e.GetId(),
		Severity:    strings.ToLower(strings.TrimPrefix(e.GetSeverity().String(), "SystemEvent_")),
		Category:    strings.ToLower(strings.TrimPrefix(e.GetCategory().String(), "SystemEvent_")),
		Message:     e.GetMessage(),
		UserMessage: e.GetUserMessage(),
		Metadata:    map[string]string{},
	}
	if ts := e.GetTimestamp(); ts != nil {
		out.Timestamp = ts.GetSeconds()
	}
	for k, v := range e.GetMetadata() {
		out.Metadata[k] = v
	}
	return out
}

// isDaemonUnreachable reports whether a gRPC stream error indicates the
// daemon socket itself is not answering (process down, socket missing,
// permission denied) versus the daemon responding with an application-level
// error code. Only the former should flip the tray to "Not running" — a
// daemon that returns FailedPrecondition (e.g. while it's retrying the
// management connection) is alive and shouldn't be reported as down.
func isDaemonUnreachable(err error) bool {
	if err == nil {
		return false
	}
	st, ok := status.FromError(err)
	if !ok {
		return true
	}
	return st.Code() == codes.Unavailable
}
