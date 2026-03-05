package metrics

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// influxSample is a single InfluxDB line protocol entry.
type influxSample struct {
	measurement string
	tags        string
	fields      map[string]float64
	timestamp   time.Time
}

// influxDBMetrics collects metric events as timestamped samples.
// Each event is recorded with its exact timestamp, pushed once, then cleared.
type influxDBMetrics struct {
	mu      sync.Mutex
	samples []influxSample
}

func newInfluxDBMetrics() metricsImplementation {
	return &influxDBMetrics{}
}

func (m *influxDBMetrics) RecordConnectionStages(
	_ context.Context,
	agentInfo AgentInfo,
	connectionType ConnectionType,
	isReconnection bool,
	timestamps ConnectionStageTimestamps,
) {
	var signalingReceivedToConnection, connectionToWgHandshake, totalDuration float64

	if !timestamps.SignalingReceived.IsZero() && !timestamps.ConnectionReady.IsZero() {
		signalingReceivedToConnection = timestamps.ConnectionReady.Sub(timestamps.SignalingReceived).Seconds()
	}

	if !timestamps.ConnectionReady.IsZero() && !timestamps.WgHandshakeSuccess.IsZero() {
		connectionToWgHandshake = timestamps.WgHandshakeSuccess.Sub(timestamps.ConnectionReady).Seconds()
	}

	if !timestamps.SignalingReceived.IsZero() && !timestamps.WgHandshakeSuccess.IsZero() {
		totalDuration = timestamps.WgHandshakeSuccess.Sub(timestamps.SignalingReceived).Seconds()
	}

	attemptType := "initial"
	if isReconnection {
		attemptType = "reconnection"
	}

	connTypeStr := connectionType.String()
	tags := fmt.Sprintf("deployment_type=%s,connection_type=%s,attempt_type=%s,version=%s,os=%s",
		agentInfo.DeploymentType.String(),
		connTypeStr,
		attemptType,
		agentInfo.Version,
		agentInfo.OS,
	)

	now := time.Now()

	m.mu.Lock()
	defer m.mu.Unlock()

	m.samples = append(m.samples, influxSample{
		measurement: "netbird_peer_connection",
		tags:        tags,
		fields: map[string]float64{
			"signaling_to_connection_seconds":    signalingReceivedToConnection,
			"connection_to_wg_handshake_seconds": connectionToWgHandshake,
			"total_seconds":                      totalDuration,
		},
		timestamp: now,
	})

	log.Tracef("peer connection metrics [%s, %s, %s]: signalingReceived→connection: %.3fs, connection→wg_handshake: %.3fs, total: %.3fs",
		agentInfo.DeploymentType.String(), connTypeStr, attemptType, signalingReceivedToConnection, connectionToWgHandshake, totalDuration)
}

func (m *influxDBMetrics) RecordSyncDuration(_ context.Context, agentInfo AgentInfo, duration time.Duration) {
	tags := fmt.Sprintf("deployment_type=%s,version=%s,os=%s",
		agentInfo.DeploymentType.String(),
		agentInfo.Version,
		agentInfo.OS,
	)

	m.mu.Lock()
	defer m.mu.Unlock()

	m.samples = append(m.samples, influxSample{
		measurement: "netbird_sync",
		tags:        tags,
		fields: map[string]float64{
			"duration_seconds": duration.Seconds(),
		},
		timestamp: time.Now(),
	})
}

// Export writes pending samples in InfluxDB line protocol format.
// Format: measurement,tag=val,tag=val field=val,field=val timestamp_ns
func (m *influxDBMetrics) Export(w io.Writer) error {
	m.mu.Lock()
	samples := make([]influxSample, len(m.samples))
	copy(samples, m.samples)
	m.mu.Unlock()

	for _, s := range samples {
		if _, err := fmt.Fprintf(w, "%s,%s ", s.measurement, s.tags); err != nil {
			return err
		}

		first := true
		for k, v := range s.fields {
			if !first {
				if _, err := fmt.Fprint(w, ","); err != nil {
					return err
				}
			}
			if _, err := fmt.Fprintf(w, "%s=%g", k, v); err != nil {
				return err
			}
			first = false
		}

		if _, err := fmt.Fprintf(w, " %d\n", s.timestamp.UnixNano()); err != nil {
			return err
		}
	}
	return nil
}

// Reset clears pending samples after a successful push
func (m *influxDBMetrics) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.samples = m.samples[:0]
}