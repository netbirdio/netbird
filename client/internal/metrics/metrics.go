package metrics

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/metrics/remoteconfig"
)

// AgentInfo holds static information about the agent
type AgentInfo struct {
	DeploymentType DeploymentType
	Version        string
	OS             string // runtime.GOOS (linux, darwin, windows, etc.)
	Arch           string // runtime.GOARCH (amd64, arm64, etc.)
	peerID         string // anonymised peer identifier (SHA-256 of WireGuard public key)
}

// peerIDFromPublicKey returns a truncated SHA-256 hash (8 bytes / 16 hex chars) of the given WireGuard public key.
func peerIDFromPublicKey(pubKey string) string {
	hash := sha256.Sum256([]byte(pubKey))
	return hex.EncodeToString(hash[:8])
}

// connectionPairID returns a deterministic identifier for a connection between two peers.
// It sorts the two peer IDs before hashing so the same pair always produces the same ID
// regardless of which side computes it.
func connectionPairID(peerID1, peerID2 string) string {
	a, b := peerID1, peerID2
	if a > b {
		a, b = b, a
	}
	hash := sha256.Sum256([]byte(a + b))
	return hex.EncodeToString(hash[:8])
}

// metricsImplementation defines the internal interface for metrics implementations
type metricsImplementation interface {
	// RecordConnectionStages records connection stage metrics from timestamps
	RecordConnectionStages(
		ctx context.Context,
		agentInfo AgentInfo,
		connectionPairID string,
		connectionType ConnectionType,
		isReconnection bool,
		timestamps ConnectionStageTimestamps,
	)

	// RecordSyncDuration records how long it took to process a sync message
	RecordSyncDuration(ctx context.Context, agentInfo AgentInfo, duration time.Duration)

	// RecordSyncPhase records how long a single sub-phase of sync processing took
	RecordSyncPhase(ctx context.Context, agentInfo AgentInfo, phase string, duration time.Duration)

	// RecordLoginDuration records how long the login to management took
	RecordLoginDuration(ctx context.Context, agentInfo AgentInfo, duration time.Duration, success bool)

	// RecordVNCSessionTick records a periodic snapshot of one VNC
	// session's wire activity. Called once per metricsConn tick interval
	// (and once at session close), only when the tick saw activity.
	RecordVNCSessionTick(ctx context.Context, agentInfo AgentInfo, tick VNCSessionTick)

	// Export exports metrics in InfluxDB line protocol format
	Export(w io.Writer) error

	// Reset clears all collected metrics
	Reset()
}

type ClientMetrics struct {
	impl metricsImplementation

	agentInfo AgentInfo
	mu        sync.RWMutex

	push       atomic.Pointer[Push]
	pushMu     sync.Mutex
	wg         sync.WaitGroup
	pushCancel context.CancelFunc
}

// VNCSessionTick is one sampling slice of a VNC session's wire activity.
// BytesOut / Writes / FBUs / WriteNanos are deltas observed during this
// tick; Max* fields are the high-water marks observed during the tick.
// Period is the wall-clock duration the deltas cover.
type VNCSessionTick struct {
	Period        time.Duration
	BytesOut      uint64
	Writes        uint64
	FBUs          uint64
	MaxFBUBytes   uint64
	MaxFBURects   uint64
	MaxWriteBytes uint64
	WriteNanos    uint64
}

// ConnectionStageTimestamps holds timestamps for each connection stage
type ConnectionStageTimestamps struct {
	SignalingReceived  time.Time // First signal received from remote peer (both initial and reconnection)
	ConnectionReady    time.Time
	WgHandshakeSuccess time.Time
}

// String returns a human-readable representation of the connection stage timestamps
func (c ConnectionStageTimestamps) String() string {
	return fmt.Sprintf("ConnectionStageTimestamps{SignalingReceived=%v, ConnectionReady=%v, WgHandshakeSuccess=%v}",
		c.SignalingReceived.Format(time.RFC3339Nano),
		c.ConnectionReady.Format(time.RFC3339Nano),
		c.WgHandshakeSuccess.Format(time.RFC3339Nano),
	)
}

// RecordConnectionStages calculates stage durations from timestamps and records them.
// remotePubKey is the remote peer's WireGuard public key; it will be hashed for anonymisation.
func (c *ClientMetrics) RecordConnectionStages(
	ctx context.Context,
	remotePubKey string,
	connectionType ConnectionType,
	isReconnection bool,
	timestamps ConnectionStageTimestamps,
) {
	if c == nil {
		return
	}
	c.mu.RLock()
	agentInfo := c.agentInfo
	c.mu.RUnlock()

	remotePeerID := peerIDFromPublicKey(remotePubKey)
	pairID := connectionPairID(agentInfo.peerID, remotePeerID)
	c.impl.RecordConnectionStages(ctx, agentInfo, pairID, connectionType, isReconnection, timestamps)
}

// RecordSyncDuration records the duration of sync message processing
func (c *ClientMetrics) RecordSyncDuration(ctx context.Context, duration time.Duration) {
	if c == nil {
		return
	}
	c.mu.RLock()
	agentInfo := c.agentInfo
	c.mu.RUnlock()

	c.impl.RecordSyncDuration(ctx, agentInfo, duration)
}

// RecordVNCSessionTick records a periodic snapshot of one VNC session.
func (c *ClientMetrics) RecordVNCSessionTick(ctx context.Context, tick VNCSessionTick) {
	if c == nil {
		return
	}
	c.mu.RLock()
	agentInfo := c.agentInfo
	c.mu.RUnlock()

	c.impl.RecordVNCSessionTick(ctx, agentInfo, tick)
}

// RecordSyncPhase records the duration of a single sub-phase of sync processing
func (c *ClientMetrics) RecordSyncPhase(ctx context.Context, phase string, duration time.Duration) {
	if c == nil {
		return
	}
	c.mu.RLock()
	agentInfo := c.agentInfo
	c.mu.RUnlock()

	c.impl.RecordSyncPhase(ctx, agentInfo, phase, duration)
}

// RecordLoginDuration records how long the login to management server took
func (c *ClientMetrics) RecordLoginDuration(ctx context.Context, duration time.Duration, success bool) {
	if c == nil {
		return
	}
	c.mu.RLock()
	agentInfo := c.agentInfo
	c.mu.RUnlock()

	c.impl.RecordLoginDuration(ctx, agentInfo, duration, success)
}

// UpdateAgentInfo updates the agent information (e.g., when switching profiles).
// publicKey is the WireGuard public key; it will be hashed for anonymisation.
func (c *ClientMetrics) UpdateAgentInfo(agentInfo AgentInfo, publicKey string) {
	if c == nil {
		return
	}

	agentInfo.peerID = peerIDFromPublicKey(publicKey)

	c.mu.Lock()
	c.agentInfo = agentInfo
	c.mu.Unlock()

	if push := c.push.Load(); push != nil {
		push.SetPeerID(agentInfo.peerID)
	}
}

// Export exports metrics to the writer
func (c *ClientMetrics) Export(w io.Writer) error {
	if c == nil {
		return nil
	}

	return c.impl.Export(w)
}

// StartPush starts periodic pushing of metrics with the given configuration.
// Precedence: PushConfig.ServerAddress > remote config server_url
func (c *ClientMetrics) StartPush(ctx context.Context, config PushConfig) {
	if c == nil {
		return
	}

	c.pushMu.Lock()
	defer c.pushMu.Unlock()

	if c.push.Load() != nil {
		log.Warnf("metrics push already running")
		return
	}

	c.startPushLocked(ctx, config)
}

// StopPush stops the periodic metrics push.
func (c *ClientMetrics) StopPush() {
	if c == nil {
		return
	}
	c.pushMu.Lock()
	defer c.pushMu.Unlock()

	c.stopPushLocked()
}

// UpdatePushFromMgm updates metrics push based on management server configuration.
// If NB_METRICS_PUSH_ENABLED is explicitly set (true or false), management config is ignored.
// When unset, management controls whether push is enabled.
func (c *ClientMetrics) UpdatePushFromMgm(ctx context.Context, enabled bool) {
	if c == nil {
		return
	}

	if isMetricsPushEnvSet() {
		log.Debugf("ignoring management config, env var is explicitly set: %s", EnvMetricsPushEnabled)
		return
	}

	c.pushMu.Lock()
	defer c.pushMu.Unlock()

	if enabled {
		if c.push.Load() != nil {
			return
		}
		log.Infof("enabled metrics push by management")
		c.startPushLocked(ctx, PushConfigFromEnv())
	} else {
		if c.push.Load() == nil {
			return
		}
		log.Infof("disabled metrics push by management")
		c.stopPushLocked()
	}
}

// startPushLocked starts push. Caller must hold pushMu.
func (c *ClientMetrics) startPushLocked(ctx context.Context, config PushConfig) {
	c.mu.RLock()
	agentVersion := c.agentInfo.Version
	peerID := c.agentInfo.peerID
	c.mu.RUnlock()

	configManager := remoteconfig.NewManager(getMetricsConfigURL(), remoteconfig.DefaultMinRefreshInterval)
	push, err := NewPush(c.impl, configManager, config, agentVersion)
	if err != nil {
		log.Errorf("failed to create metrics push: %v", err)
		return
	}
	push.SetPeerID(peerID)

	ctx, cancel := context.WithCancel(ctx)
	c.pushCancel = cancel
	c.push.Store(push)

	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		push.Start(ctx)
		c.push.CompareAndSwap(push, nil)
	}()
}

// stopPushLocked stops push. Caller must hold pushMu.
func (c *ClientMetrics) stopPushLocked() {
	if c.push.Load() == nil {
		return
	}

	c.pushCancel()
	c.wg.Wait()
	c.push.Store(nil)
}
