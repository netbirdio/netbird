//go:build !ios && !android

package cmd

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/netbirdio/netbird/client/proto"
)

func grpcGatewayEndpoint(addr string) string {
	return strings.TrimPrefix(addr, "tcp://")
}

func (p *program) startJSONGateway(jsonListener *socketListener, daemonEndpoint string) error {
	mux := runtime.NewServeMux()
	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	if err := proto.RegisterDaemonServiceHandlerFromEndpoint(p.ctx, mux, grpcGatewayEndpoint(daemonEndpoint), opts); err != nil {
		return err
	}

	jsonServer := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		BaseContext: func(net.Listener) context.Context {
			return p.ctx
		},
	}

	p.jsonServMu.Lock()
	p.jsonServ = jsonServer
	p.jsonServMu.Unlock()

	go func() {
		log.Printf("started daemon JSON server: %v", jsonListener.address)
		if err := jsonServer.Serve(jsonListener.Listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Errorf("failed to serve daemon JSON requests: %v", err)
		}
	}()

	return nil
}
