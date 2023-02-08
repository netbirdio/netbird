package dns

import (
	"context"
	"errors"
	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	failsTillDeact   = int32(3)
	reactivatePeriod = time.Minute
	upstreamTimeout  = 15 * time.Second
)

type upstreamResolver struct {
	ctx              context.Context
	upstreamClient   *dns.Client
	upstreamServers  []string
	disabled         bool
	failsCount       atomic.Int32
	failsTillDeact   int32
	mutex            sync.Mutex
	reactivatePeriod time.Duration
	upstreamTimeout  time.Duration

	deactivate func()
	reactivate func()
}

func newUpstreamResolver(ctx context.Context) *upstreamResolver {
	return &upstreamResolver{
		ctx:              ctx,
		upstreamClient:   &dns.Client{},
		upstreamTimeout:  upstreamTimeout,
		reactivatePeriod: reactivatePeriod,
		failsTillDeact:   failsTillDeact,
	}
}

// ServeDNS handles a DNS request
func (u *upstreamResolver) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	defer u.checkUpstreamFails()

	log.WithField("question", r.Question[0]).Trace("received an upstream question")

	select {
	case <-u.ctx.Done():
		return
	default:
	}

	for _, upstream := range u.upstreamServers {
		ctx, cancel := context.WithTimeout(u.ctx, u.upstreamTimeout)
		rm, t, err := u.upstreamClient.ExchangeContext(ctx, r, upstream)

		cancel()

		if err != nil {
			if err == context.DeadlineExceeded || isTimeout(err) {
				log.WithError(err).WithField("upstream", upstream).
					Warn("got an error while connecting to upstream")
				continue
			}
			u.failsCount.Add(1)
			log.WithError(err).WithField("upstream", upstream).
				Error("got an error while querying the upstream")
			return
		}

		log.Tracef("took %s to query the upstream %s", t, upstream)

		err = w.WriteMsg(rm)
		if err != nil {
			log.WithError(err).Error("got an error while writing the upstream resolver response")
		}
		// count the fails only if they happen sequentially
		u.failsCount.Store(0)
		return
	}
	u.failsCount.Add(1)
	log.Error("all queries to the upstream nameservers failed with timeout")
}

// checkUpstreamFails counts fails and disables or enables upstream resolving
//
// If fails count is greater that failsTillDeact, upstream resolving
// will be disabled for reactivatePeriod, after that time period fails counter
// will be reset and upstream will be reactivated.
func (u *upstreamResolver) checkUpstreamFails() {
	u.mutex.Lock()
	defer u.mutex.Unlock()

	if u.failsCount.Load() < u.failsTillDeact || u.disabled {
		return
	}

	log.WithField("preiod", reactivatePeriod).Warn("upstream resolving is disabled for")
	u.deactivate()
	u.disabled = true
	go u.waitUntilReactivation()
}

// waitUntilReactivation reset fails counter and activates upstream resolving
func (u *upstreamResolver) waitUntilReactivation() {
	timer := time.NewTimer(u.reactivatePeriod)
	defer func() {
		if !timer.Stop() {
			<-timer.C
		}
	}()

	select {
	case <-u.ctx.Done():
		return
	case <-timer.C:
		log.Info("upstream resolving is reactivated")
		u.failsCount.Store(0)
		u.reactivate()
		u.disabled = false
	}
}

// isTimeout returns true if the given error is a network timeout error.
//
// Copied from k8s.io/apimachinery/pkg/util/net.IsTimeout
func isTimeout(err error) bool {
	var neterr net.Error
	if errors.As(err, &neterr) {
		return neterr != nil && neterr.Timeout()
	}
	return false
}
