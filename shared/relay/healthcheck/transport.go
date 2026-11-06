package healthcheck

import "time"

const (
	transportWS = "ws"

	streamHealthCheckInterval = 120 * time.Second
	heartbeatGrace            = 10 * time.Second
)

// IntervalFor returns the healthcheck interval the server uses on the given relay transport.
func IntervalFor(transport string) time.Duration {
	if transport == transportWS {
		return streamHealthCheckInterval
	}
	return defaultHealthCheckInterval
}

// HeartbeatTimeoutFor returns how long the client waits for a healthcheck on the given relay transport.
func HeartbeatTimeoutFor(transport string) time.Duration {
	return IntervalFor(transport) + heartbeatGrace
}
