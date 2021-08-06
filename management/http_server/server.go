package http_server

import (
	"encoding/gob"
	"fmt"
	"github.com/joho/godotenv"
	"github.com/wiretrustee/wiretrustee/management/http_server/handler"
	"github.com/wiretrustee/wiretrustee/management/http_server/middleware"
	"log"
	"net/http"
	"os"

	"github.com/codegangsta/negroni"
	"github.com/gorilla/sessions"
)

type Server struct {
	SessionStore *sessions.FilesystemStore
}

func StartServer() {

	err := godotenv.Load()
	if err != nil {
		panic(err)
	}

	authDomain := os.Getenv("AUTH0_DOMAIN")
	authClientId := os.Getenv("AUTH0_CLIENT_ID")
	authClientSecret := os.Getenv("AUTH0_CLIENT_SECRET")
	authCallback := os.Getenv("AUTH0_CALLBACK_URL")

	sessionStore := sessions.NewFilesystemStore("", []byte("something-very-secret"))
	authenticator, err := middleware.NewAuthenticator(authDomain, authClientId, authClientSecret, authCallback)
	if err != nil {
		log.Fatal(fmt.Errorf("failed cerating authentication middleware %v", err))
	}

	gob.Register(map[string]interface{}{})

	r := http.NewServeMux()

	r.Handle("/login", handler.NewLogin(authenticator, sessionStore))
	r.Handle("/logout", handler.NewLogout(authDomain, authClientId))
	r.Handle("/callback", handler.NewCallback(authenticator, sessionStore))
	r.Handle("/dashboard", negroni.New(
		negroni.HandlerFunc(middleware.NewAuth(sessionStore).IsAuthenticated),
		negroni.Wrap(handler.NewDashboard(sessionStore))),
	)
	http.Handle("/", r)
	log.Print("Server listening on http://localhost:3000/login")
	log.Fatal(http.ListenAndServe("0.0.0.0:3000", nil))
}
