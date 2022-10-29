package dns

import (
	"context"
	"fmt"
	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
	"sync"
	"time"
)

const Port = 5053
const DefaultIP = "0.0.0.0"
const DefaultUpstreamTimeout = 15 * time.Second

type Server struct {
	ctx    context.Context
	stop   context.CancelFunc
	mux    sync.Mutex
	server *dns.Server
	dnsMux *dns.ServeMux
}

func NewServer(ctx context.Context) *Server {
	mux := dns.NewServeMux()

	dnsServer := &dns.Server{
		Addr:    fmt.Sprintf("%s:%d", DefaultIP, Port),
		Net:     "udp",
		Handler: mux,
		UDPSize: 65535,
	}

	ctx, stop := context.WithCancel(ctx)

	return &Server{
		ctx:    ctx,
		stop:   stop,
		server: dnsServer,
		dnsMux: mux,
	}
}

func (s *Server) Start() {
	log.Debugf("starting dns on %s:%d", DefaultIP, Port)
	go func() {
		err := s.server.ListenAndServe()
		if err != nil {
			log.Errorf("dns server returned an error: %v", err)
		}
	}()
}

func (s *Server) Stop() {
	ctx, _ := context.WithTimeout(s.ctx, 5*time.Second)
	err := s.server.ShutdownContext(ctx)
	if err != nil {
		log.Errorf("stopping dns server returned an error: %v", err)
	}
}

func (s *Server) registerMux(pattern string, handler dns.Handler) {
	s.dnsMux.Handle(pattern, handler)
}

func (s *Server) deregisterMux(pattern string) {
	s.dnsMux.HandleRemove(pattern)
}

type upstreamHandler struct {
	parentCTX       context.Context
	upstreamClient  *dns.Client
	upstreamServers []string
}

func (u *upstreamHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {

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
			log.Errorf("got an error while writing the dns response, error: %v", err)
		}
		return
	}
}

type localHandler struct {
	peerMap sync.Map
}

func (d *localHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	var (
		response dns.RR
		err      error
	)
	log.Debugf("received question: %#v\n", r.Question[0])
	response, err = d.lookupPeerMap(r)
	if err != nil {
		log.Error(err)
		dns.HandleFailed()
	}

	replyMessage := &dns.Msg{}
	replyMessage.SetReply(r)

	if response == nil {
		// todo  handler error and empty response (not found) here and on upstream
		replyMessage.SetRcode(r, dns.Rcode)
	} else {
		replyMessage.Answer = append(replyMessage.Answer, response)
	}

	w.WriteMsg(replyMessage)
}

func (d *localHandler) lookupPeerMap(r *dns.Msg) (dns.RR, error) {
	host, found := d.peerMap.Load(r.Question[0].Name)
	if found {
		return dns.NewRR(r.Question[0].Name + " 300 IN A " + host.(string))
	}

	return nil, nil
}
