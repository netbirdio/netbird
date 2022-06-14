package http

import (
	"context"
	"crypto/tls"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	s "github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/http/handler"
	"github.com/netbirdio/netbird/management/server/http/middleware"
	"github.com/rs/cors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/acme/autocert"
)

type Server struct {
	server         *http.Server
	config         *s.HttpServerConfig
	certManager    *autocert.Manager
	tlsConfig      *tls.Config
	accountManager s.AccountManager
}

// NewHttpsServer creates a new HTTPs server (with HTTPS support) and a certManager that is responsible for generating and renewing Let's Encrypt certificate
// The listening address will be :443 no matter what was specified in s.HttpServerConfig.Address
func NewHttpsServer(
	config *s.HttpServerConfig,
	certManager *autocert.Manager,
	accountManager s.AccountManager,
) *Server {
	server := &http.Server{
		Addr:         config.Address,
		WriteTimeout: time.Second * 15,
		ReadTimeout:  time.Second * 15,
		IdleTimeout:  time.Second * 60,
	}
	return &Server{
		server:         server,
		config:         config,
		certManager:    certManager,
		accountManager: accountManager,
	}
}

// NewHttpsServerWithTLSConfig creates a new HTTPs server with a provided tls.Config.
// Usually used when you already have a certificate
func NewHttpsServerWithTLSConfig(
	config *s.HttpServerConfig,
	tlsConfig *tls.Config,
	accountManager s.AccountManager,
) *Server {
	server := &http.Server{
		Addr:         config.Address,
		WriteTimeout: time.Second * 15,
		ReadTimeout:  time.Second * 15,
		IdleTimeout:  time.Second * 60,
	}
	return &Server{
		server:         server,
		config:         config,
		tlsConfig:      tlsConfig,
		accountManager: accountManager,
	}
}

// NewHttpServer creates a new HTTP server (without HTTPS)
func NewHttpServer(config *s.HttpServerConfig, accountManager s.AccountManager) *Server {
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
	jwtMiddleware, err := middleware.NewJwtMiddleware(
		s.config.AuthIssuer,
		s.config.AuthAudience,
		s.config.AuthKeysLocation,
	)
	if err != nil {
		return err
	}

	corsMiddleware := cors.AllowAll()

	acMiddleware := middleware.NewAccessControll(
		s.config.AuthAudience,
		s.accountManager.IsUserAdmin)

	r := mux.NewRouter()
	r.Use(jwtMiddleware.Handler, corsMiddleware.Handler, acMiddleware.Handler)

	groupsHandler := handler.NewGroups(s.accountManager, s.config.AuthAudience)
	rulesHandler := handler.NewRules(s.accountManager, s.config.AuthAudience)
	peersHandler := handler.NewPeers(s.accountManager, s.config.AuthAudience)
	keysHandler := handler.NewSetupKeysHandler(s.accountManager, s.config.AuthAudience)
	userHandler := handler.NewUserHandler(s.accountManager, s.config.AuthAudience)

	r.HandleFunc("/api/peers", peersHandler.GetPeers).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/peers/{id}", peersHandler.HandlePeer).
		Methods("GET", "PUT", "DELETE", "OPTIONS")
	r.HandleFunc("/api/users", userHandler.GetUsers).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/setup-keys", keysHandler.GetKeys).Methods("GET", "POST", "OPTIONS")
	r.HandleFunc("/api/setup-keys/{id}", keysHandler.HandleKey).Methods("GET", "PUT", "OPTIONS")

	r.HandleFunc("/api/setup-keys", keysHandler.GetKeys).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/setup-keys/{id}", keysHandler.HandleKey).
		Methods("GET", "PUT", "DELETE", "OPTIONS")

	r.HandleFunc("/api/rules", rulesHandler.GetAllRulesHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/rules", rulesHandler.CreateRuleHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/rules/{id}", rulesHandler.UpdateRuleHandler).Methods("PUT", "OPTIONS")
	r.HandleFunc("/api/rules/{id}", rulesHandler.PatchRuleHandler).Methods("PATCH", "OPTIONS")
	r.HandleFunc("/api/rules/{id}", rulesHandler.GetRuleHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/rules/{id}", rulesHandler.DeleteRuleHandler).Methods("DELETE", "OPTIONS")

	r.HandleFunc("/api/groups", groupsHandler.GetAllGroupsHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/groups", groupsHandler.CreateGroupHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/groups/{id}", groupsHandler.UpdateGroupHandler).Methods("PUT", "OPTIONS")
	r.HandleFunc("/api/groups/{id}", groupsHandler.PatchGroupHandler).Methods("PATCH", "OPTIONS")
	r.HandleFunc("/api/groups/{id}", groupsHandler.GetGroupHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/groups/{id}", groupsHandler.DeleteGroupHandler).Methods("DELETE", "OPTIONS")
	http.Handle("/", r)

	if s.certManager != nil {
		// if HTTPS is enabled we reuse the listener from the cert manager
		listener := s.certManager.Listener()
		log.Infof(
			"HTTPs server listening on %s with Let's Encrypt autocert configured",
			listener.Addr(),
		)
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
