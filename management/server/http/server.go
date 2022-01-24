package http

import (
	"context"
	"crypto/tls"
	"github.com/gorilla/mux"
	"github.com/rs/cors"
	log "github.com/sirupsen/logrus"
	s "github.com/wiretrustee/wiretrustee/management/server"
	"github.com/wiretrustee/wiretrustee/management/server/http/handler"
	"github.com/wiretrustee/wiretrustee/management/server/http/middleware"
	"golang.org/x/crypto/acme/autocert"
	"net/http"
	"time"
)

type Server struct {
	server         *http.Server
	config         *s.HttpServerConfig
	certManager    *autocert.Manager
	tlsConfig      *tls.Config
	accountManager *s.AccountManager
}

// NewHttpsServer creates a new HTTPs server (with HTTPS support) and a certManager that is responsible for generating and renewing Let's Encrypt certificate
// The listening address will be :443 no matter what was specified in s.HttpServerConfig.Address
func NewHttpsServer(config *s.HttpServerConfig, certManager *autocert.Manager, accountManager *s.AccountManager) *Server {
	server := &http.Server{
		Addr:         config.Address,
		WriteTimeout: time.Second * 15,
		ReadTimeout:  time.Second * 15,
		IdleTimeout:  time.Second * 60,
	}
	return &Server{server: server, config: config, certManager: certManager, accountManager: accountManager}
}

// NewHttpsServerWithTLSConfig creates a new HTTPs server with a provided tls.Config.
// Usually used when you already have a certificate
func NewHttpsServerWithTLSConfig(config *s.HttpServerConfig, tlsConfig *tls.Config, accountManager *s.AccountManager) *Server {
	server := &http.Server{
		Addr:         config.Address,
		WriteTimeout: time.Second * 15,
		ReadTimeout:  time.Second * 15,
		IdleTimeout:  time.Second * 60,
	}
	return &Server{server: server, config: config, tlsConfig: tlsConfig, accountManager: accountManager}
}

// NewHttpServer creates a new HTTP server (without HTTPS)
func NewHttpServer(config *s.HttpServerConfig, accountManager *s.AccountManager) *Server {
	return NewHttpsServer(config, nil, accountManager)
}

// Stop stops the http server
func (s *Server) Stop(ctx context.Context) error {
	err := s.server.Shutdown(ctx)
	if err != nil {
		return err
	}
	return nil
}

// Start defines http handlers and starts the http server. Blocks until server is shutdown.
func (s *Server) Start() error {

	jwtMiddleware, err := middleware.NewJwtMiddleware(s.config.AuthIssuer, s.config.AuthAudience, s.config.AuthKeysLocation)
	if err != nil {
		return err
	}

	corsMiddleware := cors.AllowAll()

	r := mux.NewRouter()
	r.Use(jwtMiddleware.Handler, corsMiddleware.Handler)

	peersHandler := handler.NewPeers(s.accountManager, s.config.AuthAudience)
	keysHandler := handler.NewSetupKeysHandler(s.accountManager, s.config.AuthAudience)
	r.HandleFunc("/api/peers", peersHandler.GetPeers).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/peers/{id}", peersHandler.HandlePeer).Methods("GET", "PUT", "DELETE", "OPTIONS")

	r.HandleFunc("/api/setup-keys", keysHandler.GetKeys).Methods("GET", "POST", "OPTIONS")
	r.HandleFunc("/api/setup-keys/{id}", keysHandler.HandleKey).Methods("GET", "PUT", "OPTIONS")
	http.Handle("/", r)

	if s.certManager != nil {
		// if HTTPS is enabled we reuse the listener from the cert manager
		listener := s.certManager.Listener()
		log.Infof("HTTPs server listening on %s with Let's Encrypt autocert configured", listener.Addr())
		if err = http.Serve(listener, s.certManager.HTTPHandler(r)); err != nil {
			log.Errorf("failed to serve https server: %v", err)
			return err
		}
	} else if s.tlsConfig != nil {
		listener, err := tls.Listen("tcp", s.config.Address, s.tlsConfig)
		if err != nil {
			log.Errorf("failed to serve https server: %v", err)
			return err
		}
		log.Infof("HTTPs server listening on %s", listener.Addr())

		if err = http.Serve(listener, r); err != nil {
			log.Errorf("failed to serve https server: %v", err)
			return err
		}

	} else {
		log.Infof("HTTP server listening on %s", s.server.Addr)
		if err = s.server.ListenAndServe(); err != nil {
			log.Errorf("failed to serve http server: %v", err)
			return err
		}
	}

	return nil
}
