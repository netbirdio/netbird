//go:build !ios && !android

package cmd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"

	"github.com/netbirdio/netbird/client/internal/daemonaddr"
	"github.com/netbirdio/netbird/client/internal/ipcauth"
	"github.com/netbirdio/netbird/client/proto"
)

// jsonPeerIdentity is the context key under which the connecting HTTP client's
// identity is stashed for the lifetime of its connection.
type jsonPeerIdentity struct{}

// jsonPeerIdentityValue pairs the identity with whether it could be read at
// all, so an unreadable identity is forwarded as "unknown" rather than omitted.
type jsonPeerIdentityValue struct {
	id    ipcauth.Identity
	known bool
}

// jsonConnContext reads the identity of the client connecting to the JSON
// socket and stashes it on the connection's context. The gateway re-dials the
// daemon in-process, so the daemon would otherwise see every JSON request as
// coming from the daemon itself.
func jsonConnContext(ctx context.Context, c net.Conn) context.Context {
	value := jsonPeerIdentityValue{}
	id, err := ipcauth.ConnIdentity(c)
	if err != nil {
		log.Warnf("json gateway: cannot read HTTP client identity, privileged operations will be denied for this connection: %v", err)
	} else {
		value.id = id
		value.known = true
	}
	return context.WithValue(ctx, jsonPeerIdentity{}, value)
}

// forwardIdentity stamps the HTTP client's identity onto every call the gateway
// makes to the daemon.
//
// It is an interceptor on the gateway's client connection rather than a
// runtime.WithMetadata annotator because grpc-gateway skips annotators when no
// request header maps to metadata, which an HTTP/1.0 request with no Host header
// over a unix socket achieves. The daemon would then receive no marker, see its own
// identity as the transport peer, and authorize the request as the daemon itself.
// An interceptor runs for every RPC whatever the request looked like.
func forwardIdentity(ctx context.Context) context.Context {
	value, ok := ctx.Value(jsonPeerIdentity{}).(jsonPeerIdentityValue)
	if !ok {
		// No ConnContext ran for this request, so forward an unknown identity:
		// the daemon must not mistake its own identity for the client's.
		return ipcauth.WithForwardedIdentity(ctx, ipcauth.Identity{}, false)
	}
	return ipcauth.WithForwardedIdentity(ctx, value.id, value.known)
}

func forwardIdentityUnary(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
	return invoker(forwardIdentity(ctx), method, req, reply, cc, opts...)
}

func forwardIdentityStream(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	return streamer(forwardIdentity(ctx), desc, cc, method, opts...)
}

// reservedHeaderWarning limits the dropped-header warning to the first occurrence.
var reservedHeaderWarning sync.Once

// jsonIncomingHeaderMatcher keeps an HTTP client from supplying the metadata the
// gateway uses to forward its identity. grpc-gateway turns "Grpc-Metadata-<key>"
// headers into gRPC metadata and joins them ahead of what its annotators add, so
// without this filter a JSON client could send its own x-netbird-fwd-uid and the
// daemon would authorize that instead of the client's real identity.
func jsonIncomingHeaderMatcher(key string) (string, bool) {
	mapped, ok := runtime.DefaultHeaderMatcher(key)
	if !ok {
		return "", false
	}
	if ipcauth.IsReservedForwardKey(mapped) {
		// Warn once: any client can send these on every request, so warning each
		// time hands it a way to fill the log. The rest are debug-level.
		reservedHeaderWarning.Do(func() {
			log.Warnf("json gateway: dropping reserved header %q from a request: only the gateway may set the caller's identity", key)
		})
		log.Debugf("json gateway: dropping reserved header %q", key)
		return "", false
	}
	return mapped, true
}

func (p *program) startJSONGateway(jsonListener *socketListener, daemonEndpoint string) error {
	if jsonListener.network == "tcp" {
		log.Warnf("daemon JSON socket is listening on TCP (%s): callers carry no verifiable identity over TCP, "+
			"so privileged operations will be denied for JSON clients", jsonListener.address)
	}

	mux := runtime.NewServeMux(runtime.WithIncomingHeaderMatcher(jsonIncomingHeaderMatcher))

	// grpc.NewClient does not connect until the first request, so registering
	// the handler here cannot block daemon startup.
	target, opts := daemonaddr.DialTarget(daemonEndpoint)
	opts = append(opts,
		grpc.WithChainUnaryInterceptor(forwardIdentityUnary),
		grpc.WithChainStreamInterceptor(forwardIdentityStream),
	)
	conn, err := grpc.NewClient(target, opts...)
	if err != nil {
		return fmt.Errorf("create daemon client for JSON gateway: %w", err)
	}
	if err := proto.RegisterDaemonServiceHandler(p.ctx, mux, conn); err != nil {
		if cerr := conn.Close(); cerr != nil {
			log.Debugf("close daemon client after failed JSON gateway registration: %v", cerr)
		}
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
	p.jsonClient = conn
	p.jsonServMu.Unlock()

	go func() {
		log.Printf("started daemon JSON server: %v", jsonListener.address)
		if err := jsonServer.Serve(jsonListener.Listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Errorf("failed to serve daemon JSON requests: %v", err)
		}
	}()

	return nil
}
