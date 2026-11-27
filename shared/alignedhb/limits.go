package alignedhb

import "time"

// ClampPeriod returns period limited to MinPeriod to MaxPeriod. A server uses
// it on a request and a client uses it on an answer, so neither a client nor a
// buggy or hostile server can set a heartbeat that floods the other side or
// one so rare that its streams time out. The limits are constants: there is
// no period config and no flag.
func ClampPeriod(period time.Duration) time.Duration {
	return min(max(period, MinPeriod), MaxPeriod)
}
