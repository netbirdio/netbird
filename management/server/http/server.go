package http

import (
	"context"
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
	accountManager *s.AccountManager
}

// NewHttpsServer creates a new HTTPs server (with HTTPS support)
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

	r := http.NewServeMux()
	s.server.Handler = r

	// serve public website
	fs := http.FileServer(http.Dir("management/server/http/public"))
	r.Handle("/", fs)
	fsStatic := http.FileServer(http.Dir("management/server/http/public/static"))
	r.Handle("/static/", http.StripPrefix("/static/", fsStatic))

	r.Handle("/api", jwtMiddleware.Handler(handler.NewPeers()))
	http.Handle("/", r)

	if s.certManager != nil {
		// if HTTPS is enabled we reuse the listener from the cert manager
		listener := s.certManager.Listener()
		log.Infof("http server listening on %s", listener.Addr())
		if err = http.Serve(listener, s.certManager.HTTPHandler(r)); err != nil {
			log.Errorf("failed to serve https server: %v", err)
			return err
		}
	} else {
		log.Infof("http server listening on %s", s.server.Addr)
		if err = s.server.ListenAndServe(); err != nil {
			log.Errorf("failed to serve http server: %v", err)
			return err
		}
	}

	return nil
}
