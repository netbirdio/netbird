package filedrop

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

const (
	defaultSpoolMaxAge = 24 * time.Hour
	janitorInterval    = 10 * time.Minute
	readHeaderTimeout  = 30 * time.Second
	idleTimeout        = 5 * time.Minute
)

// PeerResolver maps the source overlay address of a connection to the peer that owns it.
type PeerResolver interface {
	ResolvePeer(addr netip.Addr) (key PeerKey, name string, ok bool)
}

// Notifier receives receiver-side transfer events for the platform layer to surface.
type Notifier interface {
	OnOffer(offer Offer)
	OnProgress(offer Offer, index int, received int64)
	OnCompleted(offer Offer)
	OnFailed(offer Offer, err error)
	OnWithdrawn(offer Offer)
}

// ServerConfig configures the receiving side. Sink overrides the filesystem
// spool, for a platform that stages payloads somewhere the engine cannot
// address; SpoolDir is then unused.
type ServerConfig struct {
	SpoolDir    string
	Sink        Sink
	Policy      *PolicyStore
	Resolver    PeerResolver
	Notifier    Notifier
	OfferTTL    time.Duration
	SpoolMaxAge time.Duration
}

// ListenControl is a raw-socket hook applied to host listeners before bind,
// mirroring net.ListenConfig.Control.
type ListenControl func(network, address string, c syscall.RawConn) error

// Server serves the receiver over HTTP on the overlay address and owns the
// listener and janitor lifecycle; the protocol logic itself lives in receiver.
type Server struct {
	mu             sync.RWMutex
	httpServer     *http.Server
	listener       net.Listener
	extraListeners []net.Listener
	netstackNet    *netstack.Net
	listenControl  ListenControl

	recv      *receiver
	boundPort uint16

	janitorStop context.CancelFunc
	janitorDone chan struct{}
}

// NewServer builds a receiving server. It does not start listening.
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.Resolver == nil {
		return nil, errors.New("peer resolver is required")
	}
	if cfg.Policy == nil {
		return nil, errors.New("receiving policy is required")
	}

	spool := cfg.Sink
	if spool == nil {
		fsSpool, err := NewSpool(cfg.SpoolDir)
		if err != nil {
			return nil, fmt.Errorf("create spool: %w", err)
		}
		spool = fsSpool
	}

	maxAge := cfg.SpoolMaxAge
	if maxAge <= 0 {
		maxAge = defaultSpoolMaxAge
	}

	return &Server{recv: newReceiver(cfg, spool, maxAge)}, nil
}

// SetListenControl installs a raw-socket hook applied to host listeners.
func (s *Server) SetListenControl(control ListenControl) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.listenControl = control
}

// SetNetstackNet routes listeners through the gVisor netstack instead of host sockets.
func (s *Server) SetNetstackNet(n *netstack.Net) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.netstackNet = n
}

// Offers returns the offer store, for the platform layer to accept, decline, and list.
func (s *Server) Offers() *OfferStore {
	return s.recv.offers
}

// Spool returns the staging area, so the platform layer can deliver completed payloads.
func (s *Server) Spool() Sink {
	return s.recv.spool
}

// FileSpool returns the staging area as a filesystem spool, nil when the
// platform staged payloads elsewhere.
func (s *Server) FileSpool() *Spool {
	spool, _ := s.recv.spool.(*Spool)
	return spool
}

// Policy returns the active profile's receiving policy store.
func (s *Server) Policy() *PolicyStore {
	return s.recv.policy
}

// BoundPort returns the port the server actually listens on, 0 when stopped.
func (s *Server) BoundPort() uint16 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.boundPort
}

// Start binds the service to addr and serves until Stop.
func (s *Server) Start(ctx context.Context, addr netip.AddrPort) error {
	s.mu.Lock()
	if s.httpServer != nil {
		s.mu.Unlock()
		return errors.New("file drop server is already running")
	}

	ln, desc, err := s.createListener(ctx, addr)
	if err != nil && addr.Port() != 0 {
		log.Warnf("file drop port %d is unavailable, falling back to a dynamic port: %v", addr.Port(), err)
		ln, desc, err = s.createListener(ctx, netip.AddrPortFrom(addr.Addr(), 0))
	}
	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("create listener: %w", err)
	}

	transport := &httpTransport{recv: s.recv}
	httpServer := &http.Server{
		Handler:           transport.routes(),
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       idleTimeout,
	}

	janitorCtx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	s.listener = ln
	s.httpServer = httpServer
	s.boundPort = listenerPort(ln, addr.Port())
	s.janitorStop = cancel
	s.janitorDone = done
	s.mu.Unlock()

	go s.runJanitor(janitorCtx, done)
	go s.serve(httpServer, ln, desc)

	log.Infof("file drop server started on %s", desc)
	return nil
}

// AddListener serves the running service on an additional address, such as IPv6.
func (s *Server) AddListener(ctx context.Context, addr netip.AddrPort) error {
	s.mu.Lock()
	httpServer := s.httpServer
	if httpServer == nil {
		s.mu.Unlock()
		return errors.New("file drop server is not running")
	}

	ln, desc, err := s.createListener(ctx, addr)
	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("create listener: %w", err)
	}
	s.extraListeners = append(s.extraListeners, ln)
	s.mu.Unlock()

	go s.serve(httpServer, ln, desc)

	log.Infof("file drop server also listening on %s", desc)
	return nil
}

// Stop shuts the service down and releases the offers it was tracking. It is idempotent.
func (s *Server) Stop() error {
	s.mu.Lock()
	httpServer := s.httpServer
	if httpServer == nil {
		s.mu.Unlock()
		return nil
	}
	s.httpServer = nil
	s.listener = nil
	s.boundPort = 0
	extra := s.extraListeners
	s.extraListeners = nil
	stopJanitor, janitorDone := s.janitorStop, s.janitorDone
	s.janitorStop, s.janitorDone = nil, nil
	s.mu.Unlock()

	if stopJanitor != nil {
		stopJanitor()
		<-janitorDone
	}

	err := httpServer.Close()

	for _, ln := range extra {
		if cerr := ln.Close(); cerr != nil {
			log.Debugf("close extra file drop listener: %v", cerr)
		}
	}

	s.recv.close()

	if err != nil {
		return fmt.Errorf("close: %w", err)
	}
	return nil
}

func (s *Server) serve(httpServer *http.Server, ln net.Listener, desc string) {
	if err := httpServer.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Errorf("file drop server error on %s: %v", desc, err)
	}
}

func (s *Server) createListener(ctx context.Context, addr netip.AddrPort) (net.Listener, string, error) {
	if s.netstackNet != nil {
		ln, err := s.netstackNet.ListenTCPAddrPort(addr)
		if err != nil {
			return nil, "", fmt.Errorf("listen on netstack: %w", err)
		}
		return ln, fmt.Sprintf("netstack %s", addr), nil
	}

	lc := net.ListenConfig{Control: s.listenControl}
	ln, err := lc.Listen(ctx, "tcp", net.TCPAddrFromAddrPort(addr).String())
	if err != nil {
		return nil, "", fmt.Errorf("listen: %w", err)
	}
	return ln, addr.String(), nil
}

func (s *Server) runJanitor(ctx context.Context, done chan struct{}) {
	defer close(done)

	ticker := time.NewTicker(janitorInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.recv.expireOverdue()
		}
	}
}

func listenerPort(ln net.Listener, requested uint16) uint16 {
	if tcpAddr, ok := ln.Addr().(*net.TCPAddr); ok {
		return uint16(tcpAddr.Port)
	}
	return requested
}
