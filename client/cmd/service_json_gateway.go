//go:build !ios && !android

package cmd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/netbirdio/netbird/client/internal/ipcauth"
	"github.com/netbirdio/netbird/client/proto"
)

// jsonPeerCtxKey keys the HTTP client's kernel identity in the request context.
type jsonPeerCtxKey struct{}

// jsonConnContext reads the connecting HTTP client's identity from the JSON
// socket (peercred) and stashes it so it can be forwarded to the daemon. The
// gateway re-dials the daemon as the daemon's own identity, so without this the
// daemon would see every JSON request as privileged.
func jsonConnContext(ctx context.Context, c net.Conn) context.Context {
	id, err := ipcauth.ConnIdentity(c)
	if err != nil {
		log.Debugf("json gateway: cannot read HTTP client identity, requests won't carry it: %v", err)
		return ctx
	}
	return context.WithValue(ctx, jsonPeerCtxKey{}, id)
}

// jsonForwardIdentity injects the stashed HTTP client identity as gRPC metadata
// on the gateway's re-dial to the daemon. The daemon trusts it only because the
// dial arrives as the daemon's own (self/privileged) identity.
func jsonForwardIdentity(ctx context.Context, _ *http.Request) metadata.MD {
	id, ok := ctx.Value(jsonPeerCtxKey{}).(ipcauth.Identity)
	if !ok {
		return nil
	}
	return ipcauth.ForwardIdentityMetadata(id)
}

func (p *program) startJSONGateway(jsonListener *socketListener, daemonEndpoint string) error {
	mux := runtime.NewServeMux(runtime.WithMetadata(jsonForwardIdentity))

	// Lazy client to the daemon, npipe-aware (grpc.NewClient does not connect
	// until the first request, so this does not block startup before Serve).
	target, opts := daemonDialTarget(daemonEndpoint)
	conn, err := grpc.NewClient(target, opts...)
	if err != nil {
		return fmt.Errorf("create daemon client for JSON gateway: %w", err)
	}
	if err := proto.RegisterDaemonServiceHandler(p.ctx, mux, conn); err != nil {
		return err
	}

	jsonServer := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		BaseContext: func(net.Listener) context.Context {
			return p.ctx
		},
		ConnContext: jsonConnContext,
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
