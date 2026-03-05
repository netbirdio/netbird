package metrics

import (
	"context"
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
}

// metricsImplementation defines the internal interface for metrics implementations
type metricsImplementation interface {
	// RecordConnectionStages records connection stage metrics from timestamps
	RecordConnectionStages(
		ctx context.Context,
		agentInfo AgentInfo,
		connectionType ConnectionType,
		isReconnection bool,
		timestamps ConnectionStageTimestamps,
	)

	// RecordSyncDuration records how long it took to process a sync message
	RecordSyncDuration(ctx context.Context, agentInfo AgentInfo, duration time.Duration)

	// Export exports metrics in Prometheus format
	Export(w io.Writer) error
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

// NewClientMetrics creates a new ClientMetrics instance
func NewClientMetrics(agentInfo AgentInfo) *ClientMetrics {
	return &ClientMetrics{
		impl:      newVictoriaMetrics(),
		agentInfo: agentInfo,
	}
}

// RecordConnectionStages calculates stage durations from timestamps and records them
func (c *ClientMetrics) RecordConnectionStages(
	ctx context.Context,
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

	c.impl.RecordConnectionStages(ctx, agentInfo, connectionType, isReconnection, timestamps)
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

// UpdateAgentInfo updates the agent information (e.g., when switching profiles)
func (c *ClientMetrics) UpdateAgentInfo(agentInfo AgentInfo) {
	if c == nil {
		return
	}

	c.mu.Lock()
	oldDeploymentType := c.agentInfo.DeploymentType
	c.agentInfo = agentInfo
	c.mu.Unlock()

	if oldDeploymentType != agentInfo.DeploymentType {
		log.Infof("metrics deployment type updated: %s -> %s",
			oldDeploymentType.String(), agentInfo.DeploymentType.String())
	}
}

// Export exports metrics to the writer
func (c *ClientMetrics) Export(w io.Writer) error {
	if c == nil {
		return nil
	}
	return c.impl.Export(w)
}

// StartPush starts periodic pushing of metrics with the given configuration
// Precedence: config parameter > env var > DefaultPushConfig
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

	ctx, cancel := context.WithCancel(ctx)
	c.pushCancel = cancel

	c.mu.RLock()
	agentVersion := c.agentInfo.Version
	c.mu.RUnlock()

	configManager := remoteconfig.NewManager(getMetricsConfigURL(), remoteconfig.DefaultMinRefreshInterval)
	push := NewPush(c.impl, configManager, config, agentVersion)
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		push.Start(ctx)
	}()
	c.push = push

	if push.overrideInterval > 0 {
		log.Infof("started metrics push to %s with override interval %s", push.pushURL, push.overrideInterval)
	} else {
		log.Infof("started metrics push to %s with remote config", push.pushURL)
	}
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
}
