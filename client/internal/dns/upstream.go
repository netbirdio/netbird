package dns

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/hashicorp/go-multierror"
	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/internal/dns/types"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/proto"
)

const (
	UpstreamTimeout = 15 * time.Second

	failsTillDeact   = int32(5)
	reactivatePeriod = 30 * time.Second
	probeTimeout     = 2 * time.Second
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
	domain           string
	disabled         bool
	failsCount       atomic.Int32
	successCount     atomic.Int32
	failsTillDeact   int32
	mutex            sync.Mutex
	reactivatePeriod time.Duration
	upstreamTimeout  time.Duration

	deactivate     func(error)
	reactivate     func()
	statusRecorder *peer.Status
}

func newUpstreamResolverBase(ctx context.Context, statusRecorder *peer.Status, domain string) *upstreamResolverBase {
	ctx, cancel := context.WithCancel(ctx)

	return &upstreamResolverBase{
		ctx:              ctx,
		cancel:           cancel,
		domain:           domain,
		upstreamTimeout:  UpstreamTimeout,
		reactivatePeriod: reactivatePeriod,
		failsTillDeact:   failsTillDeact,
		statusRecorder:   statusRecorder,
	}
}

// String returns a string representation of the upstream resolver
func (u *upstreamResolverBase) String() string {
	return fmt.Sprintf("upstream %v", u.upstreamServers)
}

// ID returns the unique handler ID
func (u *upstreamResolverBase) ID() types.HandlerID {
	servers := slices.Clone(u.upstreamServers)
	slices.Sort(servers)

	hash := sha256.New()
	hash.Write([]byte(u.domain + ":"))
	hash.Write([]byte(strings.Join(servers, ",")))
	return types.HandlerID("upstream-" + hex.EncodeToString(hash.Sum(nil)[:8]))
}

func (u *upstreamResolverBase) MatchSubdomains() bool {
	return true
}

func (u *upstreamResolverBase) Stop() {
	log.Debugf("stopping serving DNS for upstreams %s", u.upstreamServers)
	u.cancel()
}

// ServeDNS handles a DNS request
func (u *upstreamResolverBase) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	requestID := GenerateRequestID()
	logger := log.WithField("request_id", requestID)
	var err error
	defer func() {
		u.checkUpstreamFails(err)
	}()

	logger.Tracef("received upstream question: domain=%s type=%v class=%v", r.Question[0].Name, r.Question[0].Qtype, r.Question[0].Qclass)
	if r.Extra == nil {
		r.MsgHdr.AuthenticatedData = true
	}

	select {
	case <-u.ctx.Done():
		logger.Tracef("%s has been stopped", u)
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
				logger.Warnf("upstream %s timed out for question domain=%s", upstream, r.Question[0].Name)
				continue
			}
			logger.Warnf("failed to query upstream %s for question domain=%s: %s", upstream, r.Question[0].Name, err)
			continue
		}

		if rm == nil || !rm.Response {
			logger.Warnf("no response from upstream %s for question domain=%s", upstream, r.Question[0].Name)
			continue
		}

		u.successCount.Add(1)
		logger.Tracef("took %s to query the upstream %s for question domain=%s", t, upstream, r.Question[0].Name)

		if err = w.WriteMsg(rm); err != nil {
			logger.Errorf("failed to write DNS response for question domain=%s: %s", r.Question[0].Name, err)
		}
		// count the fails only if they happen sequentially
		u.failsCount.Store(0)
		return
	}
	u.failsCount.Add(1)
	logger.Errorf("all queries to the %s failed for question domain=%s", u, r.Question[0].Name)

	m := new(dns.Msg)
	m.SetRcode(r, dns.RcodeServerFailure)
	if err := w.WriteMsg(m); err != nil {
		logger.Errorf("failed to write error response for %s for question domain=%s: %s", u, r.Question[0].Name, err)
	}
}

// checkUpstreamFails counts fails and disables or enables upstream resolving
//
// If fails count is greater that failsTillDeact, upstream resolving
// will be disabled for reactivatePeriod, after that time period fails counter
// will be reset and upstream will be reactivated.
func (u *upstreamResolverBase) checkUpstreamFails(err error) {
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

	u.disable(err)

	if u.statusRecorder == nil {
		return
	}

	u.statusRecorder.PublishEvent(
		proto.SystemEvent_WARNING,
		proto.SystemEvent_DNS,
		"All upstream servers failed (fail count exceeded)",
		"Unable to reach one or more DNS servers. This might affect your ability to connect to some services.",
		map[string]string{"upstreams": strings.Join(u.upstreamServers, ", ")},
		// TODO add domain meta
	)
}

// ProbeAvailability tests all upstream servers simultaneously and
// disables the resolver if none work
func (u *upstreamResolverBase) ProbeAvailability() {
	u.mutex.Lock()
	defer u.mutex.Unlock()

	select {
	case <-u.ctx.Done():
		return
	default:
	}

	// avoid probe if upstreams could resolve at least one query and fails count is less than failsTillDeact
	if u.successCount.Load() > 0 && u.failsCount.Load() < u.failsTillDeact {
		return
	}

	var success bool
	var mu sync.Mutex
	var wg sync.WaitGroup

	var errors *multierror.Error
	for _, upstream := range u.upstreamServers {
		upstream := upstream

		wg.Add(1)
		go func() {
			defer wg.Done()
			err := u.testNameserver(upstream, 500*time.Millisecond)
			if err != nil {
				errors = multierror.Append(errors, err)
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
		u.disable(errors.ErrorOrNil())

		if u.statusRecorder == nil {
			return
		}

		u.statusRecorder.PublishEvent(
			proto.SystemEvent_WARNING,
			proto.SystemEvent_DNS,
			"All upstream servers failed (probe failed)",
			"Unable to reach one or more DNS servers. This might affect your ability to connect to some services.",
			map[string]string{"upstreams": strings.Join(u.upstreamServers, ", ")},
		)
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
			if err := u.testNameserver(upstream, probeTimeout); err != nil {
				log.Tracef("upstream check for %s: %s", upstream, err)
			} else {
				// at least one upstream server is available, stop probing
				return nil
			}
		}

		log.Tracef("checking connectivity with upstreams %s failed. Retrying in %s", u.upstreamServers, exponentialBackOff.NextBackOff())
		return fmt.Errorf("upstream check call error")
	}

	err := backoff.Retry(operation, exponentialBackOff)
	if err != nil {
		log.Warn(err)
		return
	}

	log.Infof("upstreams %s are responsive again. Adding them back to system", u.upstreamServers)
	u.failsCount.Store(0)
	u.successCount.Add(1)
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

func (u *upstreamResolverBase) disable(err error) {
	if u.disabled {
		return
	}

	log.Warnf("Upstream resolving is Disabled for %v", reactivatePeriod)
	u.successCount.Store(0)
	u.deactivate(err)
	u.disabled = true
	go u.waitUntilResponse()
}

func (u *upstreamResolverBase) testNameserver(server string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(u.ctx, timeout)
	defer cancel()

	r := new(dns.Msg).SetQuestion(testRecord, dns.TypeSOA)

	_, _, err := u.upstreamClient.exchange(ctx, server, r)
	return err
}

// ExchangeWithFallback exchanges a DNS message with the upstream server.
// It first tries to use UDP, and if it is truncated, it falls back to TCP.
// If the passed context is nil, this will use Exchange instead of ExchangeContext.
func ExchangeWithFallback(ctx context.Context, client *dns.Client, r *dns.Msg, upstream string) (*dns.Msg, time.Duration, error) {
	// MTU - ip + udp headers
	// Note: this could be sent out on an interface that is not ours, but our MTU should always be lower.
	client.UDPSize = iface.DefaultMTU - (60 + 8)

	var (
		rm  *dns.Msg
		t   time.Duration
		err error
	)

	if ctx == nil {
		rm, t, err = client.Exchange(r, upstream)
	} else {
		rm, t, err = client.ExchangeContext(ctx, r, upstream)
	}

	if err != nil {
		return nil, t, fmt.Errorf("with udp: %w", err)
	}

	if rm == nil || !rm.MsgHdr.Truncated {
		return rm, t, nil
	}

	log.Tracef("udp response for domain=%s type=%v class=%v is truncated, trying TCP.",
		r.Question[0].Name, r.Question[0].Qtype, r.Question[0].Qclass)

	client.Net = "tcp"

	if ctx == nil {
		rm, t, err = client.Exchange(r, upstream)
	} else {
		rm, t, err = client.ExchangeContext(ctx, r, upstream)
	}

	if err != nil {
		return nil, t, fmt.Errorf("with tcp: %w", err)
	}

	// TODO: once TCP is implemented, rm.Truncate() if the request came in over UDP

	return rm, t, nil
}

func GenerateRequestID() string {
	bytes := make([]byte, 4)
	_, err := rand.Read(bytes)
	if err != nil {
		log.Errorf("failed to generate request ID: %v", err)
		return ""
	}
	return hex.EncodeToString(bytes)
}
