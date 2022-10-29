package dns

import (
	"context"
	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
	"time"
)

const DefaultUpstreamTimeout = 15 * time.Second

type upstreamResolver struct {
	parentCTX       context.Context
	upstreamClient  *dns.Client
	upstreamServers []string
}

func (u *upstreamResolver) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {

	log.Debugf("received an upstream question: %#v", r.Question[0])

	select {
	case <-u.parentCTX.Done():
		return
	default:
	}

	ctx, cancel := context.WithTimeout(u.parentCTX, DefaultUpstreamTimeout)
	defer cancel()

	for _, upstream := range u.upstreamServers {
		rm, t, err := u.upstreamClient.ExchangeContext(ctx, r, upstream)
		log.Debugf("took %s to query the upstream\n", t)
		if err != nil {
			if err == context.DeadlineExceeded {
				log.Errorf("got an error while connecting to upstream %s, error: %v", upstream, err)
				continue
			}
			log.Errorf("got an error while querying the upstream %s, error: %v", upstream, err)
			return
		}
		err = w.WriteMsg(rm)
		if err != nil {
			log.Errorf("got an error while writing the upstream resolver response, error: %v", err)
		}
		return
	}
}
