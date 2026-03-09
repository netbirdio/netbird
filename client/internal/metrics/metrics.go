package metrics

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/metrics/remoteconfig"
)

// AgentInfo holds static information about the agent
type AgentInfo struct {
	DeploymentType DeploymentType
	Version        string
	OS             string // runtime.GOOS (linux, darwin, windows, etc.)
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

	// Export exports metrics in Prometheus format
	Export(w io.Writer) error

	// Reset clears all collected metrics
	Reset()
}

type ClientMetrics struct {
	impl metricsImplementation

	agentInfo AgentInfo
	mu        sync.RWMutex

	push       *Push
	pushMu     sync.Mutex
	wg         sync.WaitGroup
	pushCancel context.CancelFunc
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
}

// Export exports metrics to the writer
func (c *ClientMetrics) Export(w io.Writer) error {
	if c == nil {
		return nil
	}

	return c.impl.Export(w)
}

// StartPush starts periodic pushing of metrics with the given configuration
// Precedence: PushConfig.ServerAddress > remote config server_url
func (c *ClientMetrics) StartPush(ctx context.Context, config PushConfig) {
	if c == nil {
		return
	}

	c.pushMu.Lock()
	defer c.pushMu.Unlock()

	if c.push != nil {
		log.Warnf("metrics push already running")
		return
	}

	c.mu.RLock()
	agentVersion := c.agentInfo.Version
	c.mu.RUnlock()

	configManager := remoteconfig.NewManager(getMetricsConfigURL(), remoteconfig.DefaultMinRefreshInterval)
	push, err := NewPush(c.impl, configManager, config, agentVersion)
	if err != nil {
		log.Errorf("failed to create metrics push: %v", err)
		return
	}

	ctx, cancel := context.WithCancel(ctx)
	c.pushCancel = cancel

	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		push.Start(ctx)
	}()
	c.push = push
}

func (c *ClientMetrics) StopPush() {
	if c == nil {
		return
	}
	c.pushMu.Lock()
	defer c.pushMu.Unlock()
	if c.push == nil {
		return
	}

	c.pushCancel()
	c.wg.Wait()
	c.push = nil
}
