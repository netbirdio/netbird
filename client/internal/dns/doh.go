package dns

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

const (
	// EnvDoHListen enables the DNS over HTTPS listener. The value is host:port,
	// or :port to bind the address the DNS service listens on.
	EnvDoHListen = "NB_DNS_DOH_LISTEN"
	// EnvDoHCertFile is the path to the PEM certificate chain served by the
	// DNS over HTTPS listener.
	EnvDoHCertFile = "NB_DNS_DOH_CERT_FILE"
	// EnvDoHKeyFile is the path to the PEM private key for EnvDoHCertFile.
	EnvDoHKeyFile = "NB_DNS_DOH_KEY_FILE"

	dohPath        = "/dns-query"
	dohContentType = "application/dns-message"

	dohReadHeaderTimeout = 5 * time.Second
	dohIdleTimeout       = 60 * time.Second
	dohShutdownTimeout   = 2 * time.Second
)

// dohConfig is the DNS over HTTPS listener configuration taken from the
// environment.
type dohConfig struct {
	listen   string
	certFile string
	keyFile  string
}

func dohConfigFromEnv() dohConfig {
	return dohConfig{
		listen:   strings.TrimSpace(os.Getenv(EnvDoHListen)),
		certFile: strings.TrimSpace(os.Getenv(EnvDoHCertFile)),
		keyFile:  strings.TrimSpace(os.Getenv(EnvDoHKeyFile)),
	}
}

func (c dohConfig) enabled() bool {
	return c.listen != ""
}

// resolveAddr returns the address to bind. A bare ":port" binds serviceIP.
func (c dohConfig) resolveAddr(serviceIP netip.Addr) (string, error) {
	host, portStr, err := net.SplitHostPort(c.listen)
	if err != nil {
		return "", fmt.Errorf("parse %s: %w", EnvDoHListen, err)
	}

	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || port == 0 {
		return "", fmt.Errorf("parse %s: invalid port %q", EnvDoHListen, portStr)
	}

	if host == "" {
		if !serviceIP.IsValid() {
			return "", errors.New("DNS service address is not available")
		}
		return net.JoinHostPort(serviceIP.String(), portStr), nil
	}

	addr, err := netip.ParseAddr(host)
	if err != nil {
		return "", fmt.Errorf("parse %s: host must be an IP address: %w", EnvDoHListen, err)
	}
	return net.JoinHostPort(addr.Unmap().String(), portStr), nil
}

func (c dohConfig) loadCertificate() (tls.Certificate, error) {
	if c.certFile == "" || c.keyFile == "" {
		return tls.Certificate{}, fmt.Errorf("%s and %s must both be set", EnvDoHCertFile, EnvDoHKeyFile)
	}

	cert, err := tls.LoadX509KeyPair(c.certFile, c.keyFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("load certificate: %w", err)
	}
	return cert, nil
}

// dohServer serves RFC 8484 DNS over HTTPS on top of a dns.Handler.
type dohServer struct {
	handler dns.Handler
	cert    tls.Certificate

	mu      sync.Mutex
	srv     *http.Server
	stopped chan struct{}
}

func newDoHServer(handler dns.Handler, cert tls.Certificate) *dohServer {
	return &dohServer{handler: handler, cert: cert}
}

// start serves on ln until stop is called. The listener is closed by stop.
func (d *dohServer) start(ln net.Listener) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.srv != nil {
		return errors.New("DoH server already started")
	}

	mux := http.NewServeMux()
	mux.HandleFunc(dohPath, d.serveHTTP)

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: dohReadHeaderTimeout,
		IdleTimeout:       dohIdleTimeout,
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{d.cert},
		},
	}
	stopped := make(chan struct{})
	d.srv = srv
	d.stopped = stopped

	go func() {
		defer close(stopped)
		if err := srv.ServeTLS(ln, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Warnf("DoH server stopped: %v", err)
		}
	}()
	return nil
}

// stop shuts the server down and waits for it to exit. It is safe to call
// more than once.
func (d *dohServer) stop() {
	d.mu.Lock()
	srv, stopped := d.srv, d.stopped
	d.srv, d.stopped = nil, nil
	d.mu.Unlock()

	if srv == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), dohShutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Debugf("DoH server shutdown: %v", err)
		_ = srv.Close()
	}
	<-stopped
}

func (d *dohServer) serveHTTP(w http.ResponseWriter, r *http.Request) {
	query, status := readDoHQuery(w, r)
	if query == nil {
		http.Error(w, http.StatusText(status), status)
		return
	}

	rw := &dohResponseWriter{local: localAddrOf(r), remote: remoteAddrOf(r)}
	d.handler.ServeDNS(rw, query)

	resp := rw.msg
	if resp == nil {
		resp = new(dns.Msg)
		resp.SetRcode(query, dns.RcodeServerFailure)
	}

	packed, err := resp.Pack()
	if err != nil {
		log.Debugf("DoH pack response: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", dohContentType)
	w.Header().Set("Cache-Control", "max-age="+strconv.FormatUint(uint64(minAnswerTTL(resp)), 10))
	if _, err := w.Write(packed); err != nil {
		log.Tracef("DoH write response: %v", err)
	}
}

// readDoHQuery extracts and unpacks the DNS message of a request as defined in
// RFC 8484 section 4.1. It returns nil and the HTTP status to answer with when
// the request is not acceptable.
func readDoHQuery(w http.ResponseWriter, r *http.Request) (*dns.Msg, int) {
	var raw []byte

	switch r.Method {
	case http.MethodGet:
		param := r.URL.Query().Get("dns")
		if param == "" {
			return nil, http.StatusBadRequest
		}
		decoded, err := base64.RawURLEncoding.DecodeString(param)
		if err != nil {
			return nil, http.StatusBadRequest
		}
		raw = decoded
	case http.MethodPost:
		if mediaType(r.Header.Get("Content-Type")) != dohContentType {
			return nil, http.StatusUnsupportedMediaType
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, dns.MaxMsgSize))
		if err != nil {
			return nil, http.StatusRequestEntityTooLarge
		}
		raw = body
	default:
		w.Header().Set("Allow", "GET, POST")
		return nil, http.StatusMethodNotAllowed
	}

	if len(raw) > dns.MaxMsgSize {
		return nil, http.StatusRequestEntityTooLarge
	}

	query := new(dns.Msg)
	if err := query.Unpack(raw); err != nil || query.Response || len(query.Question) == 0 {
		return nil, http.StatusBadRequest
	}
	return query, 0
}

func mediaType(contentType string) string {
	mt, _, _ := strings.Cut(contentType, ";")
	return strings.ToLower(strings.TrimSpace(mt))
}

// minAnswerTTL returns the smallest TTL of the answer section, which RFC 8484
// section 5.1 uses as the HTTP freshness lifetime. A message without answers
// reports 0 so it is not cached by HTTP intermediaries.
func minAnswerTTL(m *dns.Msg) uint32 {
	if len(m.Answer) == 0 {
		return 0
	}
	ttl := m.Answer[0].Header().Ttl
	for _, rr := range m.Answer[1:] {
		ttl = min(ttl, rr.Header().Ttl)
	}
	return ttl
}

func remoteAddrOf(r *http.Request) net.Addr {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return &net.TCPAddr{}
	}
	return net.TCPAddrFromAddrPort(netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()))
}

func localAddrOf(r *http.Request) net.Addr {
	if addr, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
		return addr
	}
	return &net.TCPAddr{}
}

// certFingerprint returns the SHA-256 fingerprint of the leaf certificate, for
// logs and for admins comparing what they distributed.
func certFingerprint(cert tls.Certificate) string {
	if len(cert.Certificate) == 0 {
		return ""
	}
	sum := sha256.Sum256(cert.Certificate[0])
	return hex.EncodeToString(sum[:])
}

// dohResponseWriter captures the reply a dns.Handler writes so it can be sent
// as an HTTP response.
type dohResponseWriter struct {
	local  net.Addr
	remote net.Addr
	msg    *dns.Msg
}

func (w *dohResponseWriter) LocalAddr() net.Addr  { return w.local }
func (w *dohResponseWriter) RemoteAddr() net.Addr { return w.remote }

func (w *dohResponseWriter) WriteMsg(m *dns.Msg) error {
	w.msg = m
	return nil
}

func (w *dohResponseWriter) Write(b []byte) (int, error) {
	m := new(dns.Msg)
	if err := m.Unpack(b); err != nil {
		return 0, fmt.Errorf("unpack response: %w", err)
	}
	w.msg = m
	return len(b), nil
}

func (w *dohResponseWriter) Close() error        { return nil }
func (w *dohResponseWriter) TsigStatus() error   { return nil }
func (w *dohResponseWriter) TsigTimersOnly(bool) {}
func (w *dohResponseWriter) Hijack()             {}

// startDoH starts the DNS over HTTPS listener when it is configured. The
// caller must hold s.mux. Any failure leaves the listener off and is logged:
// a listener that cannot be set up must not take the resolver down.
func (s *DefaultServer) startDoH() {
	if s.doh != nil {
		return
	}

	cfg := dohConfigFromEnv()
	if !cfg.enabled() {
		return
	}

	cert, err := cfg.loadCertificate()
	if err != nil {
		log.Warnf("DoH listener not started: %v", err)
		return
	}

	addr, err := cfg.resolveAddr(s.service.RuntimeIP())
	if err != nil {
		log.Warnf("DoH listener not started: %v", err)
		return
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Warnf("DoH listener not started: listen on %s: %v", addr, err)
		return
	}

	doh := newDoHServer(s.handlerChain, cert)
	if err := doh.start(ln); err != nil {
		_ = ln.Close()
		log.Warnf("DoH listener not started: %v", err)
		return
	}
	s.doh = doh

	log.Infof("DoH listener started on %s%s, certificate sha256 %s", ln.Addr(), dohPath, certFingerprint(cert))
}

// stopDoH stops the DNS over HTTPS listener. The caller must hold s.mux.
func (s *DefaultServer) stopDoH() {
	if s.doh == nil {
		return
	}
	s.doh.stop()
	s.doh = nil
	log.Info("DoH listener stopped")
}
