package alignedhb

import "time"

// ReceiveMargin is how long past the period a receiver waits for a heartbeat
// before it counts the stream as dead. It covers arrival jitter and one TCP
// resend.
const ReceiveMargin = 10 * time.Second

// ReceiveTimeout returns how long a receiver waits for the next heartbeat on a
// stream with heartbeats every period.
func ReceiveTimeout(period time.Duration) time.Duration {
	return period + ReceiveMargin
}

// TCPKeepAliveIdle returns the TCP keepalive idle time for a connection that
// carries heartbeats every period. A heartbeat and its ACK reset the idle
// timer on both ends, so no probe goes out on a live connection.
func TCPKeepAliveIdle(period time.Duration) time.Duration {
	return 2 * period
}
