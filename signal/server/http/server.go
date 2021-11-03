package http

import (
	"context"
	"encoding/base64"
	pb "github.com/golang/protobuf/proto" //nolint
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
	"github.com/wiretrustee/wiretrustee/signal/peer"
	"github.com/wiretrustee/wiretrustee/signal/proto"
	"golang.org/x/crypto/acme/autocert"
	"net/http"
	"time"
)

type Server struct {
	server      *http.Server
	certManager *autocert.Manager
	registry    *peer.Registry
}

func NewHttpsServer(addr string, certManager *autocert.Manager, registry *peer.Registry) *Server {

	server := &http.Server{
		Addr:         addr,
		WriteTimeout: time.Second * 15,
		ReadTimeout:  time.Second * 15,
		IdleTimeout:  time.Second * 60,
	}

	return &Server{
		server:      server,
		certManager: certManager,
		registry:    registry,
	}
}

func NewHttpServer(addr string, registry *peer.Registry) *Server {
	return NewHttpsServer(addr, nil, registry)
}

// Stop stops the http server
func (s *Server) Stop(ctx context.Context) error {
	err := s.server.Shutdown(ctx)
	if err != nil {
		return err
	}
	return nil
}

func (s *Server) Start() error {

	r := mux.NewRouter()

	r.HandleFunc("/signal", func(w http.ResponseWriter, r *http.Request) {
		s.serveWs(w, r)
	})

	http.Handle("/", r)

	if s.certManager != nil {
		// if HTTPS is enabled we reuse the listener from the cert manager
		listener := s.certManager.Listener()
		log.Infof("HTTPs server listening on %s with Let's Encrypt autocert configured", listener.Addr())
		if err := http.Serve(listener, s.certManager.HTTPHandler(r)); err != nil {
			log.Errorf("failed to serve https server: %v", err)
			return err
		}
	} else {
		log.Infof("HTTP server listening on %s", s.server.Addr)
		if err := s.server.ListenAndServe(); err != nil {
			log.Errorf("failed to serve http server: %v", err)
			return err
		}
	}

	return nil
}

// serveWs handles websocket requests from the peer.
func (s *Server) serveWs(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true //TODO not good to allow everything
		},
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Errorf("failed upgrading Websocket request %v", err)
		//http.Error(w, "failed upgrading Websocket request", http.StatusInternalServerError)
		return
	}

	params := r.URL.Query()
	peerId := params.Get("id")
	if peerId == "" {
		log.Warn("required Websocket query id parameter is missing")
		//http.Error(w, "required Websocket query id parameter is missing", http.StatusBadRequest)
		conn.Close()
		return
	}

	decodeString, err := base64.URLEncoding.DecodeString(peerId)
	if err != nil {
		conn.Close()
		return
	}
	channel := peer.NewWebsocketChannel(conn)
	p := peer.NewPeer(string(decodeString), channel)
	s.registry.Register(p)

	defer func() {
		s.registry.Deregister(p)
		conn.Close()
	}()

	conn.SetReadLimit(1024 * 1024 * 3)
	for {
		t, byteMsg, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("error: %v", err, t)
			}
			break
		}

		msg := &proto.EncryptedMessage{}
		err = pb.Unmarshal(byteMsg, msg)
		if err != nil {
			//todo
			return
		}

		if dstPeer, found := s.registry.Get(msg.RemoteKey); found {
			//forward the message to the target peer
			err := dstPeer.Stream.Send(msg)
			if err != nil {
				log.Errorf("error while forwarding message from peer [%s] to peer [%s]", p.Id, msg.RemoteKey)
				//todo respond to the sender?
			} else {
				log.Debugf("forwarded message from peer %s to peer %s", msg.Key, msg.RemoteKey)
			}
		} else {
			log.Warnf("message from peer [%s] can't be forwarded to peer [%s] because destination peer is not connected", p.Id, msg.RemoteKey)
			//todo respond to the sender?
		}
	}
}
