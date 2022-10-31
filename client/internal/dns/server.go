package dns

import (
	"context"
	"fmt"
	"github.com/miekg/dns"
	nbdns "github.com/netbirdio/netbird/dns"
	log "github.com/sirupsen/logrus"
	"sync"
	"time"
)

const (
	Port      = 5053
	DefaultIP = "0.0.0.0"
)

type Server struct {
	ctx           context.Context
	stop          context.CancelFunc
	mux           sync.Mutex
	server        *dns.Server
	dnsMux        *dns.ServeMux
	dnsMuxMap     registrationMap
	localResolver *localResolver
	updateSerial  uint64
}

type registrationMap map[string]struct{}

type muxUpdate struct {
	domain  string
	handler dns.Handler
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
		ctx:       ctx,
		stop:      stop,
		server:    dnsServer,
		dnsMux:    mux,
		dnsMuxMap: make(registrationMap),
		localResolver: &localResolver{
			registeredMap: make(registrationMap),
		},
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
	s.stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	err := s.server.ShutdownContext(ctx)
	if err != nil {
		log.Errorf("stopping dns server returned an error: %v", err)
	}
	cancel()
}

func (s *Server) UpdateDNSServer(serial uint64, update nbdns.Update) error {
	select {
	case <-s.ctx.Done():
		log.Infof("not updating DNS server as context is closed")
		return s.ctx.Err()
	default:
		if serial < s.updateSerial {
			log.Debugf("not applying dns update, error: "+
				"network update is %d behind the last applied update", s.updateSerial-serial)
			return nil
		}
		s.mux.Lock()
		defer s.mux.Unlock()

		localMuxUpdates, localRecords := s.buildLocalHandlerUpdate(update.CustomZones)
		upstreamMuxUpdates, err := s.buildUpstreamHandlerUpdate(update.NameServerGroups)
		if err != nil {
			return fmt.Errorf("not applying dns update, error: %v", err)
		}

		muxUpdates := append(localMuxUpdates, upstreamMuxUpdates...)

		s.updateMux(muxUpdates)
		s.updateLocalResolver(localRecords)

		s.updateSerial = serial

		return nil
	}
}

func (s *Server) buildLocalHandlerUpdate(customZones []nbdns.CustomZone) ([]muxUpdate, map[string]nbdns.SimpleRecord) {
	var muxUpdates []muxUpdate
	localRecords := make(map[string]nbdns.SimpleRecord, 0)

	for _, customZone := range customZones {
		muxUpdates = append(muxUpdates, muxUpdate{
			domain:  customZone.Domain,
			handler: s.localResolver,
		})

		for _, record := range customZone.Records {
			localRecords[record.Name] = record
		}
	}
	return muxUpdates, localRecords
}

func (s *Server) buildUpstreamHandlerUpdate(nameServerGroups []nbdns.NameServerGroup) ([]muxUpdate, error) {
	var muxUpdates []muxUpdate
	for _, nsGroup := range nameServerGroups {
		if len(nsGroup.NameServers) == 0 {
			return nil, fmt.Errorf("received a nameserver group with empty nameserver list")
		}
		handler := &upstreamResolver{
			parentCTX:      s.ctx,
			upstreamClient: &dns.Client{},
		}
		for _, ns := range nsGroup.NameServers {
			if ns.NSType != nbdns.UDPNameServerType {
				log.Warnf("skiping nameserver %s with type %s, this peer supports only %s",
					ns.IP.String(), ns.NSType.String(), nbdns.UDPNameServerType.String())
				continue
			}
			handler.upstreamServers = append(handler.upstreamServers, getNSHostPort(ns))
		}

		if len(handler.upstreamServers) == 0 {
			log.Errorf("received a nameserver group with an invalid nameserver list")
			continue
		}

		if nsGroup.Primary {
			muxUpdates = append(muxUpdates, muxUpdate{
				domain:  nbdns.RootZone,
				handler: handler,
			})
			continue
		}

		for _, domain := range nsGroup.Domains {
			if domain == "" {
				return nil, fmt.Errorf("received a non primary nameserver group with an empty domain list")
			}
			muxUpdates = append(muxUpdates, muxUpdate{
				domain:  domain,
				handler: handler,
			})
		}
	}
	return muxUpdates, nil
}

func (s *Server) updateMux(muxUpdates []muxUpdate) {
	muxUpdateMap := make(registrationMap)

	for _, update := range muxUpdates {
		s.registerMux(update.domain, update.handler)
		muxUpdateMap[update.domain] = struct{}{}
	}

	for key := range s.dnsMuxMap {
		_, found := muxUpdateMap[key]
		if !found {
			s.deregisterMux(key)
		}
	}

	s.dnsMuxMap = muxUpdateMap
}

func (s *Server) updateLocalResolver(update map[string]nbdns.SimpleRecord) {
	for key := range s.localResolver.registeredMap {
		_, found := update[key]
		if !found {
			s.localResolver.deleteRecord(key)
		}
	}

	updatedMap := make(registrationMap)
	for key, record := range update {
		err := s.localResolver.registerRecord(record)
		if err != nil {
			log.Warnf("got an error while registering the record (%s), error: %v", record.String(), err)
		}
		updatedMap[key] = struct{}{}
	}

	s.localResolver.registeredMap = updatedMap
}

func getNSHostPort(ns nbdns.NameServer) string {
	return fmt.Sprintf("%s:%d", ns.IP.String(), ns.Port)
}

func (s *Server) registerMux(pattern string, handler dns.Handler) {
	s.dnsMux.Handle(pattern, handler)
}

func (s *Server) deregisterMux(pattern string) {
	s.dnsMux.HandleRemove(pattern)
}
