package http_server

import (
	"encoding/gob"
	"github.com/joho/godotenv"
	"github.com/wiretrustee/wiretrustee/management/http_server/handler"
	"github.com/wiretrustee/wiretrustee/management/http_server/middleware"
	"log"
	"net/http"
	"os"

	"github.com/codegangsta/negroni"
	"github.com/gorilla/mux"
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
		panic(err)
	}

	gob.Register(map[string]interface{}{})

	r := mux.NewRouter()

	r.HandleFunc("/login", handler.NewLogin(authenticator, sessionStore).Handle)
	r.HandleFunc("/logout", handler.NewLogout().Handle)
	r.HandleFunc("/callback", handler.NewCallback(authenticator, sessionStore).Handle)
	r.Handle("/dashboard", negroni.New(
		negroni.HandlerFunc(middleware.NewAuth(sessionStore).IsAuthenticated),
		negroni.Wrap(http.HandlerFunc(handler.NewDashboard(sessionStore).Handle)),
	))
	r.PathPrefix("/public/").Handler(http.StripPrefix("/public/", http.FileServer(http.Dir("public/"))))
	http.Handle("/", r)
	log.Print("Server listening on http://localhost:3000/login")
	log.Fatal(http.ListenAndServe("0.0.0.0:3000", nil))
}
