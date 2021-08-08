package http

import (
	"context"
	"encoding/gob"
	log "github.com/sirupsen/logrus"
	s "github.com/wiretrustee/wiretrustee/management/server"
	"github.com/wiretrustee/wiretrustee/management/server/http/handler"
	"github.com/wiretrustee/wiretrustee/management/server/http/middleware"
	"golang.org/x/crypto/acme/autocert"
	"net/http"
	"time"

	"github.com/codegangsta/negroni"
	"github.com/gorilla/sessions"
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
	var keyPairs [][]byte
	for k, v := range s.config.Session.CookieCodecs {
		keyPairs = append(keyPairs, []byte(k), []byte(v))
	}
	sessionStore := sessions.NewFilesystemStore("", keyPairs...)
	authenticator, err := middleware.NewAuthenticator(s.config.AuthDomain, s.config.AuthClientId, s.config.AuthClientSecret, s.config.AuthCallback)
	if err != nil {
		log.Errorf("failed cerating authentication middleware %v", err)
		return err
	}

	gob.Register(map[string]interface{}{})

	r := http.NewServeMux()
	s.server.Handler = r

	r.Handle("/login", handler.NewLogin(authenticator, sessionStore, s.config.Session.MaxAgeSec, s.config.Session.CookieDomain))
	r.Handle("/logout", handler.NewLogout(s.config.AuthDomain, s.config.AuthClientId, sessionStore))
	r.Handle("/callback", handler.NewCallback(authenticator, sessionStore, s.accountManager, s.config.Session.MaxAgeSec, s.config.Session.CookieDomain))
	r.Handle("/dashboard", negroni.New(
		negroni.HandlerFunc(middleware.NewAuth(sessionStore).IsAuthenticated),
		negroni.Wrap(handler.NewDashboard(sessionStore))),
	)
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
