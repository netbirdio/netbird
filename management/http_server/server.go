package http_server

import (
	"context"
	"encoding/gob"
	log "github.com/sirupsen/logrus"
	"github.com/wiretrustee/wiretrustee/management/http_server/handler"
	"github.com/wiretrustee/wiretrustee/management/http_server/middleware"
	s "github.com/wiretrustee/wiretrustee/management/server"
	"net/http"
	"time"

	"github.com/codegangsta/negroni"
	"github.com/gorilla/sessions"
)

type Server struct {
	server *http.Server
	config *s.HttpServerConfig
}

func NewServer(config *s.HttpServerConfig) *Server {
	server := &http.Server{
		Addr:         config.Address,
		WriteTimeout: time.Second * 15,
		ReadTimeout:  time.Second * 15,
		IdleTimeout:  time.Second * 60,
	}
	return &Server{server: server, config: config}
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

	sessionStore := sessions.NewFilesystemStore("", []byte("something-very-secret"))
	authenticator, err := middleware.NewAuthenticator(s.config.AuthDomain, s.config.AuthClientId, s.config.AuthClientSecret, s.config.AuthCallback)
	if err != nil {
		log.Errorf("failed cerating authentication middleware %v", err)
		return err
	}

	gob.Register(map[string]interface{}{})

	r := http.NewServeMux()
	s.server.Handler = r

	r.Handle("/login", handler.NewLogin(authenticator, sessionStore))
	r.Handle("/logout", handler.NewLogout(s.config.AuthDomain, s.config.AuthClientId))
	r.Handle("/callback", handler.NewCallback(authenticator, sessionStore))
	r.Handle("/dashboard", negroni.New(
		negroni.HandlerFunc(middleware.NewAuth(sessionStore).IsAuthenticated),
		negroni.Wrap(handler.NewDashboard(sessionStore))),
	)
	http.Handle("/", r)

	log.Infof("http server listening on %s", s.config.Address)

	if err = s.server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}

	return nil
}
