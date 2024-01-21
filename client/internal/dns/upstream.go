package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

const (
	failsTillDeact   = int32(5)
	reactivatePeriod = 30 * time.Second
	upstreamTimeout  = 15 * time.Second
	probeTimeout     = 2 * time.Second
)

const testRecord = "."

type upstreamClient interface {
	exchange(upstream string, r *dns.Msg) (*dns.Msg, time.Duration, error)
	exchangeContext(ctx context.Context, upstream string, r *dns.Msg) (*dns.Msg, time.Duration, error)
}

type UpstreamResolver interface {
	serveDNS(r *dns.Msg) (*dns.Msg, time.Duration, error)
	upstreamExchange(upstream string, r *dns.Msg) (*dns.Msg, time.Duration, error)
}

type upstreamResolverBase struct {
	ctx              context.Context
	cancel           context.CancelFunc
	upstreamClient   upstreamClient
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

func newUpstreamResolverBase(parentCTX context.Context) *upstreamResolverBase {
	ctx, cancel := context.WithCancel(parentCTX)

	return &upstreamResolverBase{
		ctx:              ctx,
		cancel:           cancel,
		upstreamTimeout:  upstreamTimeout,
		reactivatePeriod: reactivatePeriod,
		failsTillDeact:   failsTillDeact,
	}
}

func (u *upstreamResolverBase) stop() {
	log.Debugf("stopping serving DNS for upstreams %s", u.upstreamServers)
	u.cancel()
}

// ServeDNS handles a DNS request
func (u *upstreamResolverBase) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	defer u.checkUpstreamFails()

	log.WithField("question", r.Question[0]).Trace("received an upstream question")

	select {
	case <-u.ctx.Done():
		return
	default:
	}

	for _, upstream := range u.upstreamServers {

		rm, t, err := u.upstreamClient.exchange(upstream, r)

		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
				log.WithError(err).WithField("upstream", upstream).
					Warn("got an error while connecting to upstream")
				continue
			}
			u.failsCount.Add(1)
			log.WithError(err).WithField("upstream", upstream).
				Error("got other error while querying the upstream")
			return
		}

		if rm == nil {
			log.WithError(err).WithField("upstream", upstream).
				Warn("no response from upstream")
			return
		}
		// those checks need to be independent of each other due to memory address issues
		if !rm.Response {
			log.WithError(err).WithField("upstream", upstream).
				Warn("no response from upstream")
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
func (u *upstreamResolverBase) checkUpstreamFails() {
	u.mutex.Lock()
	defer u.mutex.Unlock()

	if u.failsCount.Load() < u.failsTillDeact || u.disabled {
		return
	}

	select {
	case <-u.ctx.Done():
		return
	default:
	}

	u.disable()
}

// probeAvailability tests all upstream servers simultaneously and
// disables the resolver if none work
func (u *upstreamResolverBase) probeAvailability() {
	u.mutex.Lock()
	defer u.mutex.Unlock()

	select {
	case <-u.ctx.Done():
		return
	default:
	}

	var success bool
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, upstream := range u.upstreamServers {
		upstream := upstream

		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := u.testNameserver(upstream); err != nil {
				log.Warnf("probing upstream nameserver %s: %s", upstream, err)
				return
			}

			mu.Lock()
			defer mu.Unlock()
			success = true
		}()
	}

	wg.Wait()

	// didn't find a working upstream server, let's disable and try later
	if !success {
		u.disable()
	}
}

// waitUntilResponse retries, in an exponential interval, querying the upstream servers until it gets a positive response
func (u *upstreamResolverBase) waitUntilResponse() {
	exponentialBackOff := &backoff.ExponentialBackOff{
		InitialInterval:     500 * time.Millisecond,
		RandomizationFactor: 0.5,
		Multiplier:          1.1,
		MaxInterval:         u.reactivatePeriod,
		MaxElapsedTime:      0,
		Stop:                backoff.Stop,
		Clock:               backoff.SystemClock,
	}

	operation := func() error {
		select {
		case <-u.ctx.Done():
			return backoff.Permanent(fmt.Errorf("exiting upstream retry loop for upstreams %s: parent context has been canceled", u.upstreamServers))
		default:
		}

		for _, upstream := range u.upstreamServers {
			if err := u.testNameserver(upstream); err != nil {
				log.Tracef("upstream check for %s: %s", upstream, err)
			} else {
				// at least one upstream server is available, stop probing
				return nil
			}
		}

		log.Tracef("checking connectivity with upstreams %s failed. Retrying in %s", u.upstreamServers, exponentialBackOff.NextBackOff())
		return fmt.Errorf("got an error from upstream check call")
	}

	err := backoff.Retry(operation, exponentialBackOff)
	if err != nil {
		log.Warn(err)
		return
	}

	log.Infof("upstreams %s are responsive again. Adding them back to system", u.upstreamServers)
	u.failsCount.Store(0)
	u.reactivate()
	u.disabled = false
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

func (u *upstreamResolverBase) disable() {
	if u.disabled {
		return
	}

	// todo test the deactivation logic, it seems to affect the client
	if runtime.GOOS != "ios" {
		log.Warnf("upstream resolving is Disabled for %v", reactivatePeriod)
		u.deactivate()
		u.disabled = true
		go u.waitUntilResponse()
	}
}

func (u *upstreamResolverBase) testNameserver(server string) error {
	ctx, cancel := context.WithTimeout(u.ctx, probeTimeout)
	defer cancel()

	r := new(dns.Msg).SetQuestion(testRecord, dns.TypeSOA)

	_, _, err := u.upstreamClient.exchangeContext(ctx, server, r)
	return err
}
