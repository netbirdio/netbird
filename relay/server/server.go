package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"sync"
	"time"

	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/metric"

	nberrors "github.com/netbirdio/netbird/client/errors"
	"github.com/netbirdio/netbird/relay/auth"
	"github.com/netbirdio/netbird/relay/server/listener"
	"github.com/netbirdio/netbird/relay/server/listener/quic"
	"github.com/netbirdio/netbird/relay/server/listener/ws"
)

// ListenerConfig is the configuration for the listener.
// Address: the address to bind the listener to. It could be an address behind a reverse proxy.
// TLSConfig: the TLS configuration for the listener.
type ListenerConfig struct {
	Address   string
	TLSConfig *tls.Config
}

// Server is the main entry point for the relay server.
// It is the gate between the WebSocket listener and the Relay server logic.
// In a new HTTP connection, the server will accept the connection and pass it to the Relay server via the Accept method.
type Server struct {
	relay     *Relay
	listeners []listener.Listener
}

// NewServer creates a new relay server instance.
// meter: the OpenTelemetry meter
// exposedAddress: this address will be used as the instance URL. It should be a domain:port format.
// tlsSupport: if true, the server will support TLS
// authValidator: the auth validator to use for the server
func NewServer(meter metric.Meter, exposedAddress string, tlsSupport bool, authValidator auth.Validator) (*Server, error) {
	relay, err := NewRelay(meter, exposedAddress, tlsSupport, authValidator)
	if err != nil {
		return nil, err
	}
	return &Server{
		relay:     relay,
		listeners: make([]listener.Listener, 0, 2),
	}, nil
}

// Listen starts the relay server.
func (r *Server) Listen(cfg ListenerConfig) error {
	wSListener := &ws.Listener{
		Address:   cfg.Address,
		TLSConfig: cfg.TLSConfig,
	}
	r.listeners = append(r.listeners, wSListener)

	quicListener := &quic.Listener{
		Address: cfg.Address,
	}

	if cfg.TLSConfig != nil {
		quicListener.TLSConfig = cfg.TLSConfig
	} else {
		tlsConfig, err := generateTestTLSConfig()
		if err != nil {
			return err
		}
		quicListener.TLSConfig = tlsConfig
	}
	r.listeners = append(r.listeners, quicListener)

	errChan := make(chan error, len(r.listeners))
	wg := sync.WaitGroup{}
	for _, l := range r.listeners {
		wg.Add(1)
		go func(listener listener.Listener) {
			defer wg.Done()
			errChan <- listener.Listen(r.relay.Accept)
		}(l)
	}

	wg.Wait()
	close(errChan)
	var multiErr *multierror.Error
	for err := range errChan {
		multiErr = multierror.Append(multiErr, err)
	}

	return nberrors.FormatErrorOrNil(multiErr)
}

// Shutdown stops the relay server. If there are active connections, they will be closed gracefully. In case of a context,
// the connections will be forcefully closed.
func (r *Server) Shutdown(ctx context.Context) error {
	var multiErr *multierror.Error
	for _, l := range r.listeners {
		if err := l.Shutdown(ctx); err != nil {
			multiErr = multierror.Append(multiErr, err)
		}
	}

	r.relay.Shutdown(ctx)
	return nberrors.FormatErrorOrNil(multiErr)
}

// InstanceURL returns the instance URL of the relay server.
func (r *Server) InstanceURL() string {
	return r.relay.instanceURL
}

// GenerateTestTLSConfig creates a self-signed certificate for testing
func generateTestTLSConfig() (*tls.Config, error) {
	log.Infof("generating test TLS config")
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Organization"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 180), // Valid for 180 days
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("192.168.0.10")},
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	tlsCert, err := tls.X509KeyPair(certPEM, privateKeyPEM)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"netbird-relay"},
	}, nil
}
