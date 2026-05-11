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

	"github.com/netbirdio/netbird/client/proto"
)

const (
	// EventStatus is emitted to the frontend whenever a fresh Status snapshot
	// is captured (from a poll or a stream-driven refresh).
	EventStatus = "netbird:status"
	// EventSystem is emitted for each SubscribeEvents message (DNS, network,
	// auth, connectivity categories).
	EventSystem = "netbird:event"
	// EventUpdateAvailable fires when the daemon detects a new version. The
	// metadata's enforced flag is propagated as part of the payload.
	EventUpdateAvailable = "netbird:update:available"
	// EventUpdateProgress fires when the daemon is about to start (or has
	// started) installing an update — Mode 2 enforced flow. The UI opens the
	// progress window in response.
	EventUpdateProgress = "netbird:update:progress"

	// StatusDaemonUnavailable is the synthetic Status the UI emits when the
	// daemon's gRPC socket is unreachable (daemon not running, socket
	// permission, etc.). Real daemon statuses come straight from
	// internal.Status* — none of those collide with this label.
	StatusDaemonUnavailable = "DaemonUnavailable"
)

// Emitter is what peers.Watch needs from the host application: a simple
// "send this name and payload to the frontend" hook.  The Wails app.Event
// satisfies this with its Emit method.
type Emitter interface {
	Emit(name string, data ...any) bool
}

// UpdateAvailable carries the new_version_available metadata.
type UpdateAvailable struct {
	Version  string `json:"version"`
	Enforced bool   `json:"enforced"`
}

// UpdateProgress carries the progress_window metadata.
type UpdateProgress struct {
	Action  string `json:"action"`
	Version string `json:"version"`
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
	Status        string       `json:"status"`
	DaemonVersion string       `json:"daemonVersion"`
	Management    PeerLink     `json:"management"`
	Signal        PeerLink     `json:"signal"`
	Local         LocalPeer    `json:"local"`
	Peers         []PeerStatus `json:"peers"`
	Events        []SystemEvent `json:"events"`
}

// Peers serves the dashboard data: one polled Status RPC and a long-running
// SubscribeEvents stream that re-emits every event over the Wails event bus.
type Peers struct {
	conn    DaemonConn
	emitter Emitter

	mu       sync.Mutex
	cancel   context.CancelFunc
	streamWg sync.WaitGroup
}

func NewPeers(conn DaemonConn, emitter Emitter) *Peers {
	return &Peers{conn: conn, emitter: emitter}
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

// Get returns the current daemon status snapshot.
func (s *Peers) Get(ctx context.Context) (Status, error) {
	cli, err := s.conn.Client()
	if err != nil {
		return Status{}, err
	}
	resp, err := cli.Status(ctx, &proto.StatusRequest{GetFullPeerStatus: true})
	if err != nil {
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
			emitUnavailable()
			return fmt.Errorf("subscribe status: %w", err)
		}
		for {
			resp, err := stream.Recv()
			if err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				emitUnavailable()
				return fmt.Errorf("status stream recv: %w", err)
			}
			unavailable = false
			st := statusFromProto(resp)
			log.Infof("backend event: status status=%q peers=%d", st.Status, len(st.Peers))
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
			s.fanOutUpdateEvents(ev)
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
		Status:        resp.GetStatus(),
		DaemonVersion: resp.GetDaemonVersion(),
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
	return st
}

// fanOutUpdateEvents inspects the daemon SystemEvent for update-related
// metadata keys and re-emits them as dedicated Wails events. This lets the
// tray and React update window listen for a single, narrow event instead of
// re-checking metadata on every system event they receive.
func (s *Peers) fanOutUpdateEvents(ev *proto.SystemEvent) {
	md := ev.GetMetadata()
	if md == nil {
		return
	}
	if v, ok := md["new_version_available"]; ok {
		_, enforced := md["enforced"]
		s.emitter.Emit(EventUpdateAvailable, UpdateAvailable{Version: v, Enforced: enforced})
	}
	if action, ok := md["progress_window"]; ok {
		s.emitter.Emit(EventUpdateProgress, UpdateProgress{
			Action:  action,
			Version: md["version"],
		})
	}
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
