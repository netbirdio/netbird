package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/hashicorp/go-multierror"
	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/peer"
)

const (
	failsTillDeact   = int32(5)
	reactivatePeriod = 10 * time.Second
	upstreamTimeout  = 1 * time.Second
	probeTimeout     = 500 * time.Millisecond
)

const testRecord = "com."

type upstreamClient interface {
	exchange(ctx context.Context, upstream string, r *dns.Msg) (*dns.Msg, time.Duration, error)
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
	disabled         atomic.Bool
	mutex            sync.Mutex
	upstreamTimeout  time.Duration

	deactivate     func(error)
	reactivate     func()
	statusRecorder *peer.Status
}

func newUpstreamResolverBase(ctx context.Context, statusRecorder *peer.Status) *upstreamResolverBase {
	ctx, cancel := context.WithCancel(ctx)

	resolverBase := &upstreamResolverBase{
		ctx:              ctx,
		cancel:           cancel,
		upstreamTimeout:  upstreamTimeout,
		statusRecorder:   statusRecorder,
	}

	go resolverBase.watchPeersConnStatusChanges()

	return resolverBase
}

func (u *upstreamResolverBase) watchPeersConnStatusChanges() {
	var cancelBackOff context.CancelFunc
	var dnsProbeIsRunning atomic.Bool
	exponentialBackOff := &backoff.ExponentialBackOff{
		InitialInterval:     500 * time.Millisecond,
		RandomizationFactor: 0.5,
		Multiplier:          1.1,
		MaxInterval:         5 * time.Second,
		MaxElapsedTime:      30 * time.Second,
		Stop:                backoff.Stop,
		Clock:               backoff.SystemClock,
	}

	dnsProbe := func() error {
		dnsProbeIsRunning.Store(true)
		defer func() {
			dnsProbeIsRunning.Store(false)
		}()
		u.probeAvailability()
		if u.disabled.Load() {
			return fmt.Errorf("DNS probe failed")
		}
		return nil
	}

	var mu sync.Mutex
	dnsProbeWithBackOff := func() {
		mu.Lock()
		defer func() {
			u.mutex.Lock()
			log.Infof("DNS probe finished, servers %s disabled: %t", u.upstreamServers, u.disabled.Load())
			dnsProbeIsRunning.Store(false)
			u.mutex.Unlock()
			mu.Unlock()
		}()

		var backOffCtx context.Context
		backOffCtx, cancelBackOff = context.WithCancel(context.Background())
		defer cancelBackOff()
		err := backoff.Retry(func() error {
			select {
			case <-backOffCtx.Done():
				log.Infof("dnsProbeWithBackOff: ctx canceled")
				return backoff.Permanent(backOffCtx.Err())
			case <-u.ctx.Done():
				return backoff.Permanent(fmt.Errorf("exiting upstream retry loop for upstreams %s: parent context : %s", u.upstreamServers, u.ctx.Err()))
			default:
				return dnsProbe()
			}
		}, backoff.WithContext(exponentialBackOff, backOffCtx))
		if err != nil {
			log.Warnf("DNS probe (peer ConnStatus change) stopped: %s", err)
			return
		}
	}

	for {
		select {
		case <-u.ctx.Done():
			log.Infof("stopped watching peer connections: %s", u.ctx.Err())
			return
		case <-u.statusRecorder.GetConnStatusChangeNotifier():
			if cancelBackOff != nil {
				log.Info("restart DNS probing")
				cancelBackOff()
			}

			// wait for dnsProbe to finish
			for dnsProbeIsRunning.Load() {
				log.Infof("wait for current DNS probe to return")
				time.Sleep(500 * time.Millisecond)
			}

			if u.statusRecorder.GetConnectedPeersCount() == 0 && u.areNameServersAllPrivate(u.upstreamServers) {
				log.Infof("O peers connected, disabling private upstream servers %#v", u.upstreamServers)
				u.disable(fmt.Errorf("0 peers connected"))
			} else {
				log.Infof("DNS probe (peer ConnStatus change) started, connected peers: %d", u.statusRecorder.GetConnectedPeersCount())
				go dnsProbeWithBackOff()
			}
		}
	}
}

func (u *upstreamResolverBase) areNameServersAllPrivate(nameServers []string) bool {
	u.mutex.Lock()
	defer u.mutex.Unlock()
	for _, n := range nameServers {
		ip := net.ParseIP(strings.Split(n, ":")[0])
		if !ip.IsPrivate() {
			return false
		}
	}
	return true
}

func (u *upstreamResolverBase) stop() {
	log.Debugf("stopping serving DNS for upstreams %s", u.upstreamServers)
	u.cancel()
}

// ServeDNS handles a DNS request
func (u *upstreamResolverBase) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	var err error
	log.WithField("question", r.Question[0]).Trace("received an upstream question")
	// set the AuthenticatedData flag and the EDNS0 buffer size to 4096 bytes to support larger dns records
	if r.Extra == nil {
		r.SetEdns0(4096, false)
		r.MsgHdr.AuthenticatedData = true
	}

	select {
	case <-u.ctx.Done():
		return
	default:
	}

	for _, upstream := range u.upstreamServers {
		var rm *dns.Msg
		var t time.Duration

		func() {
			ctx, cancel := context.WithTimeout(u.ctx, u.upstreamTimeout)
			defer cancel()
			rm, t, err = u.upstreamClient.exchange(ctx, upstream, r)
		}()

		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
				log.WithError(err).WithField("upstream", upstream).
					Warn("got an error while connecting to upstream")
				continue
			}
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
		return
	}
	log.Error("all queries to the upstream nameservers failed with timeout")
}

// probeViaResolution tests all upstream servers simultaneously and
// disables/enable the public resolvers
func (u *upstreamResolverBase) probeViaResolution() {
	u.mutex.Lock()
	defer u.mutex.Unlock()

	select {
	case <-u.ctx.Done():
		return
	default:
	}

	var success atomic.Bool
	var wg sync.WaitGroup

	var errors *multierror.Error
	for _, upstream := range u.upstreamServers {
		upstream := upstream

		wg.Add(1)
		go func() {
			defer wg.Done()
			err := u.testNameserver(upstream, probeTimeout)
			if err != nil {
				errors = multierror.Append(errors, err)
				log.Warnf("probing upstream nameserver %s: %s", upstream, err)
				return
			}

			success.Store(true)
		}()
	}

	wg.Wait()

	// didn't find a working upstream server, let's disable and try later
	if !success.Load() {
		u.disable(errors.ErrorOrNil())
		return
	}

	if !u.disabled.Load() {
		return
	}
	log.Infof("upstreams %s are responsive again. Adding them back to system", u.upstreamServers)
	u.reactivate()
	u.disabled.Store(false)
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

func (u *upstreamResolverBase) disable(err error) {
	if u.disabled.Load() {
		return
	}

	log.Warnf("Upstream resolving is Disabled for %v", reactivatePeriod)
	u.deactivate(err)
	u.disabled.Store(true)
}

func (u *upstreamResolverBase) testNameserver(server string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(u.ctx, timeout)
	defer cancel()

	r := new(dns.Msg).SetQuestion(testRecord, dns.TypeSOA)

	_, _, err := u.upstreamClient.exchange(ctx, server, r)
	return err
}
