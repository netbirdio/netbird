package dns

import (
	"context"
	"errors"
	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
	"net"
	"time"
)

const defaultUpstreamTimeout = 15 * time.Second

type upstreamResolver struct {
	parentCTX       context.Context
	upstreamClient  *dns.Client
	upstreamServers []string
	upstreamTimeout time.Duration
}

// ServeDNS handles a DNS request
func (u *upstreamResolver) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {

	log.Debugf("received an upstream question: %#v", r.Question[0])

	select {
	case <-u.parentCTX.Done():
		return
	default:
	}

	for _, upstream := range u.upstreamServers {
		ctx, cancel := context.WithTimeout(u.parentCTX, u.upstreamTimeout)
		rm, t, err := u.upstreamClient.ExchangeContext(ctx, r, upstream)

		cancel()

		if err != nil {
			if err == context.DeadlineExceeded || isTimeout(err) {
				log.Warnf("got an error while connecting to upstream %s, error: %v", upstream, err)
				continue
			}
			log.Errorf("got an error while querying the upstream %s, error: %v", upstream, err)
			return
		}

		log.Tracef("took %s to query the upstream %s", t, upstream)

		err = w.WriteMsg(rm)
		if err != nil {
			log.Errorf("got an error while writing the upstream resolver response, error: %v", err)
		}
		return
	}
	log.Errorf("all queries to the upstream nameservers failed with timeout")
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
