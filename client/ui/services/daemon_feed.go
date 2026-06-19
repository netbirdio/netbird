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
	EventStatusSnapshot = "netbird:status"
	// EventDaemonNotification carries each SubscribeEvents message. Auto-update
	// SystemEvents are also forwarded to updater.Holder.OnSystemEvent so the typed
	// update state needs no second daemon subscription.
	EventDaemonNotification = "netbird:event"
	// EventProfileChanged fires after a daemon-side switch (payload: the new
	// ProfileRef). The daemon emits no profile event, so this is the only signal
	// that lets a flip driven from one surface paint in the others.
	EventProfileChanged = "netbird:profile:changed"
	// EventSessionWarning is a typed sibling of EventDaemonNotification so
	// subscribers needn't filter the notification firehose. Consumers branch on
	// SessionWarning.Final to tell the T-10 event from the T-2 fallback.
	EventSessionWarning = "netbird:session:warning"

	// StatusDaemonUnavailable is the synthetic Status emitted when the daemon's
	// gRPC socket is unreachable. No internal.Status* collides with this label.
	StatusDaemonUnavailable = "DaemonUnavailable"

	// Daemon connection status strings — mirror internal.Status* in
	// client/internal/state.go.
	StatusConnected      = "Connected"
	StatusConnecting     = "Connecting"
	StatusIdle           = "Idle"
	StatusNeedsLogin     = "NeedsLogin"
	StatusLoginFailed    = "LoginFailed"
	StatusSessionExpired = "SessionExpired"

	// SeverityCritical is the lower-cased proto SystemEvent_CRITICAL severity, as
	// emitted by systemEventFromProto. Critical events bypass the notifications gate.
	SeverityCritical = "critical"
)

// Emitter sends a named payload to the frontend. Satisfied by Wails app.Event.
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

// PeerStatus is the frontend-facing shape of a daemon PeerState.
type PeerStatus struct {
	IP                         string   `json:"ip"`
	IPv6                       string   `json:"ipv6"`
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

// PeerLink is this peer's connection to its mgmt or signal server.
type PeerLink struct {
	URL       string `json:"url"`
	Connected bool   `json:"connected"`
	Error     string `json:"error,omitempty"`
}

// LocalPeer mirrors LocalPeerState.
type LocalPeer struct {
	IP       string   `json:"ip"`
	IPv6     string   `json:"ipv6"`
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
	// selected state changes, so consumers know when to re-fetch ListNetworks
	// instead of polling every snapshot.
	NetworksRevision uint64 `json:"networksRevision"`
	// SessionExpiresAt is the absolute UTC instant the SSO session expires; nil
	// when the peer is not SSO-tracked or login expiration is disabled.
	SessionExpiresAt *time.Time `json:"sessionExpiresAt,omitempty"`
}

// DaemonFeed fans the daemon's two long-running gRPC streams (SubscribeStatus,
// SubscribeEvents) out to the frontend and tray, and exposes a one-shot Status
// RPC for callers wanting the current snapshot without subscribing.
//
// Profile-switch suppression: BeginProfileSwitch makes statusStreamLoop swallow
// the transient stale Connected and Idle pushes the daemon emits during Down, so
// consumers see Connecting → new-profile-state instead of the full blink.
//
// Two flags govern the switch lifecycle, evaluated independently by
// consumeForSwitch on every push because their lifetimes differ:
//
//	switchInProgress (suppression): clears on the first real push from the new
//	    Up. Daemon-side StatusConnecting comes BEFORE any NeedsLogin, so
//	    suppression must release here before the terminal arrives.
//	switchLoginWatch (trigger):     outlives suppression. Watches for NeedsLogin
//	    / LoginFailed / SessionExpired along the Up's retry loop and emits
//	    EventTriggerLogin so the React orchestrator opens browser-login.
//
//	┌────────────────────────────────────────────┬──────────────────────────────────┐
//	│ Incoming daemon status                     │ Action                           │
//	├────────────────────────────────────────────┼──────────────────────────────────┤
//	│ Connected, Idle (while switchInProgress)   │ Suppress (the blink we hide)     │
//	│ Connecting                                 │ Emit, clear switchInProgress     │
//	│ NeedsLogin, LoginFailed, SessionExpired    │ Emit, clear both flags, also     │
//	│                                            │   emit EventTriggerLogin         │
//	│ Connected, Idle (while only login-watch)   │ Emit, clear switchLoginWatch     │
//	│ DaemonUnavailable                          │ Emit, clear both flags           │
//	│ (timeout elapsed)                          │ Clear flags, emit normally       │
//	└────────────────────────────────────────────┴──────────────────────────────────┘
type DaemonFeed struct {
	conn    DaemonConn
	emitter Emitter
	updater *updater.Holder
	// logCtl attaches/detaches the GUI file log in response to the daemon's log
	// level (a marked SystemEvent on the SubscribeEvents stream). nil when the GUI
	// doesn't manage its log (server build / not wired), in which case the marker
	// is ignored.
	logCtl LogController

	mu       sync.Mutex
	cancel   context.CancelFunc
	streamWg sync.WaitGroup

	switchMu              sync.Mutex
	switchInProgress      bool
	switchInProgressUntil time.Time
	switchLoginWatch      bool
	switchLoginWatchUntil time.Time
}

// LogController is the subset of guilog.DebugLog that DaemonFeed drives: Apply
// turns the GUI file log on/off for a daemon level; Path is the gui-client.log
// path to register with the daemon (empty when the GUI doesn't own its log).
type LogController interface {
	Apply(level string)
	Path() string
}

// NewDaemonFeed builds the feed. logCtl may be nil (server build / GUI log not
// managed), in which case log-level markers on the event stream are ignored.
func NewDaemonFeed(conn DaemonConn, emitter Emitter, updaterHolder *updater.Holder, logCtl LogController) *DaemonFeed {
	return &DaemonFeed{conn: conn, emitter: emitter, updater: updaterHolder, logCtl: logCtl}
}

// BeginProfileSwitch arms suppression for a switch from Connected/Connecting,
// where the daemon emits stale Connected updates during Down's teardown then an
// Idle before the new Up; statusStreamLoop drops those, and a synthetic
// Connecting snapshot is emitted so consumers paint optimistically. A 30s safety
// timeout clears the flag if no follow-up status arrives.
func (s *DaemonFeed) BeginProfileSwitch() {
	now := time.Now()
	s.switchMu.Lock()
	s.switchInProgress = true
	s.switchInProgressUntil = now.Add(30 * time.Second)
	s.switchLoginWatch = true
	s.switchLoginWatchUntil = now.Add(30 * time.Second)
	s.switchMu.Unlock()
	s.emitter.Emit(EventStatusSnapshot, Status{Status: StatusConnecting})
}

// CancelProfileSwitch aborts a switch midway (tray Disconnect while Connecting):
// clears suppression so the next daemon Idle paints through, and disarms the
// login-watch so the abort doesn't pop a browser-login after the user cancelled.
func (s *DaemonFeed) CancelProfileSwitch() {
	s.switchMu.Lock()
	s.switchInProgress = false
	s.switchLoginWatch = false
	s.switchMu.Unlock()
}

// Watch starts the two background stream loops. Idempotent (a second call while
// running is a no-op); both loops self-restart via exponential backoff.
func (s *DaemonFeed) Watch(ctx context.Context) {
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
func (s *DaemonFeed) ServiceShutdown() error {
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

// Get returns the current daemon status snapshot. An unreachable daemon socket
// yields Status{Status: StatusDaemonUnavailable} rather than an error, so the
// frontend keys off a single status enum without a parallel "error" path.
func (s *DaemonFeed) Get(ctx context.Context) (Status, error) {
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

// consumeForSwitch decides, for an incoming push during a profile switch,
// whether to suppress it (suppress) and whether the switch landed in a state
// needing the SSO flow (triggerLogin: NeedsLogin / SessionExpired / LoginFailed).
//
// The two flags have different lifetimes: suppression clears on Connecting, but
// the trigger watcher must survive past it to catch the eventual NeedsLogin —
// daemon-side StatusConnecting fires before loginToManagement, which is what may
// then set StatusNeedsLogin.
func (s *DaemonFeed) consumeForSwitch(st Status) (suppress, triggerLogin bool) {
	s.switchMu.Lock()
	defer s.switchMu.Unlock()

	now := time.Now()
	if s.switchInProgress && now.After(s.switchInProgressUntil) {
		s.switchInProgress = false
	}
	if s.switchLoginWatch && now.After(s.switchLoginWatchUntil) {
		s.switchLoginWatch = false
	}

	if s.switchInProgress {
		switch {
		case strings.EqualFold(st.Status, StatusConnecting),
			strings.EqualFold(st.Status, StatusNeedsLogin),
			strings.EqualFold(st.Status, StatusLoginFailed),
			strings.EqualFold(st.Status, StatusSessionExpired),
			strings.EqualFold(st.Status, StatusDaemonUnavailable):
			// New flow has begun (Up started, or daemon refused it).
			s.switchInProgress = false
		default:
			// Stale Connected from teardown or transient Idle: suppress so the
			// optimistic Connecting stays painted. Login-watch stays armed.
			return true, false
		}
	}

	if s.switchLoginWatch {
		switch {
		case strings.EqualFold(st.Status, StatusNeedsLogin),
			strings.EqualFold(st.Status, StatusLoginFailed),
			strings.EqualFold(st.Status, StatusSessionExpired):
			// SSO-needed terminal: trigger browser-login without a second click.
			s.switchLoginWatch = false
			return false, true
		case strings.EqualFold(st.Status, StatusConnected),
			strings.EqualFold(st.Status, StatusIdle),
			strings.EqualFold(st.Status, StatusDaemonUnavailable):
			// Terminal but not SSO — disarm without triggering.
			s.switchLoginWatch = false
		}
	}

	return false, false
}

// statusStreamLoop subscribes to SubscribeStatus and re-emits each snapshot on
// the Wails event bus. The first message is the current snapshot; later ones
// fire on connection-state changes only — no polling.
func (s *DaemonFeed) statusStreamLoop(ctx context.Context) {
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

	// unavailable fires the synthetic event once per outage, not on every retry.
	unavailable := false
	emitUnavailable := func() {
		if unavailable {
			return
		}
		unavailable = true
		s.emitter.Emit(EventStatusSnapshot, Status{Status: StatusDaemonUnavailable})
	}

	op := func() error {
		return s.subscribeAndStreamStatus(ctx, &unavailable, emitUnavailable)
	}

	if err := backoff.Retry(op, bo); err != nil && ctx.Err() == nil {
		log.Errorf("status stream ended: %v", err)
	}
}

// subscribeAndStreamStatus is one attempt of the status backoff loop: open
// SubscribeStatus and re-emit every snapshot until it errors. A daemon-
// unreachable failure also flips the synthetic-unavailable signal.
func (s *DaemonFeed) subscribeAndStreamStatus(ctx context.Context, unavailable *bool, emitUnavailable func()) error {
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
			return s.handleStatusRecvErr(ctx, err, emitUnavailable)
		}
		*unavailable = false
		s.emitStatus(statusFromProto(resp))
	}
}

// handleStatusRecvErr maps a SubscribeStatus Recv error into the backoff loop's
// return: ctx cancellation stops the loop, an unreachable socket flips the
// synthetic-unavailable signal, everything else is retryable.
func (s *DaemonFeed) handleStatusRecvErr(ctx context.Context, err error, emitUnavailable func()) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if isDaemonUnreachable(err) {
		emitUnavailable()
	}
	return fmt.Errorf("status stream recv: %w", err)
}

// emitStatus pushes a snapshot to the frontend, dropping the transient
// stale-Connected / Idle pushes that occur mid profile switch.
func (s *DaemonFeed) emitStatus(st Status) {
	log.Infof("backend event: status status=%q peers=%d", st.Status, len(st.Peers))
	suppress, triggerLogin := s.consumeForSwitch(st)
	if suppress {
		log.Debugf("suppressing status=%q during profile switch", st.Status)
		return
	}
	s.emitter.Emit(EventStatusSnapshot, st)
	if triggerLogin {
		s.emitter.Emit(EventTriggerLogin)
	}
}

// toastStreamLoop subscribes to SubscribeEvents and re-emits every SystemEvent
// on the Wails event bus. Local name differs from the RPC so the file's two
// streams aren't both called streamLoop.
func (s *DaemonFeed) toastStreamLoop(ctx context.Context) {
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
		return s.subscribeAndStreamEvents(ctx)
	}

	if err := backoff.Retry(op, bo); err != nil && ctx.Err() == nil {
		log.Errorf("event stream ended: %v", err)
	}
}

// subscribeAndStreamEvents is one attempt of the event backoff loop: open
// SubscribeEvents and fan out every SystemEvent until it errors.
func (s *DaemonFeed) subscribeAndStreamEvents(ctx context.Context) error {
	cli, err := s.conn.Client()
	if err != nil {
		return fmt.Errorf("get client: %w", err)
	}
	stream, err := cli.SubscribeEvents(ctx, &proto.SubscribeRequest{})
	if err != nil {
		return fmt.Errorf("subscribe: %w", err)
	}

	// Re-register the GUI log path on every (re)connect so a daemon restart
	// re-learns it. Best-effort — a failure must not abort the stream. Done even
	// when file logging is off, so the path is known ahead of any debug toggle.
	if s.logCtl != nil && s.logCtl.Path() != "" {
		if _, err := cli.RegisterUILog(ctx, &proto.RegisterUILogRequest{Path: s.logCtl.Path()}); err != nil {
			log.Warnf("register UI log path: %v", err)
		}
	}
	for {
		ev, err := stream.Recv()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("stream recv: %w", err)
		}
		s.dispatchSystemEvent(ev)
	}
}

// dispatchSystemEvent fans one daemon SystemEvent out to the frontend
// notification stream, the typed session-warning event (when the metadata
// carries one), and the updater holder (when present).
func (s *DaemonFeed) dispatchSystemEvent(ev *proto.SystemEvent) {
	se := systemEventFromProto(ev)
	log.Infof("backend event: system severity=%s category=%s msg=%q", se.Severity, se.Category, se.UserMessage)
	// Internal refresh signal (CLI-driven profile add/remove), not a notification:
	// translate and stop so it never reaches Recent Events or fires an OS toast.
	if se.Metadata[proto.MetadataKindKey] == proto.MetadataKindProfileListChanged {
		s.emitter.Emit(EventProfileChanged, ProfileRef{})
		return
	}
	// Internal control signal driving the GUI file log on/off — handle and stop
	// so it never reaches Recent Events or toasts.
	if se.Metadata[proto.MetadataKindKey] == proto.MetadataKindLogLevelChanged {
		if s.logCtl != nil {
			s.logCtl.Apply(se.Metadata[proto.MetadataLevelKey])
		}
		return
	}
	s.emitter.Emit(EventDaemonNotification, se)
	if warn, ok := authsession.WarningFromMetadata(se.Metadata); ok {
		s.emitter.Emit(EventSessionWarning, warn)
	}
	if s.updater != nil {
		s.updater.OnSystemEvent(ev)
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
			IPv6:     local.GetIpv6(),
			PubKey:   local.GetPubKey(),
			Fqdn:     local.GetFqdn(),
			Networks: append([]string{}, local.GetNetworks()...),
		},
	}

	for _, p := range full.GetPeers() {
		st.Peers = append(st.Peers, PeerStatus{
			IP:                         p.GetIP(),
			IPv6:                       p.GetIpv6(),
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

// isDaemonUnreachable reports whether a gRPC error means the daemon socket isn't
// answering, versus the daemon responding with an application-level code. Only
// the former should flip the tray to "Not running" — a daemon returning e.g.
// FailedPrecondition is alive and must not be reported as down.
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
