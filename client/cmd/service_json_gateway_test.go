//go:build !windows && !ios && !android

package cmd

import (
	"context"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"

	"github.com/netbirdio/netbird/client/internal/ipcauth"
)

// The JSON gateway runs inside the daemon and re-dials it locally, so every JSON
// request reaches a handler with the daemon's own identity as the transport peer.
// The gateway therefore forwards its HTTP client's identity as metadata, and the
// daemon authorizes that instead of itself. These tests drive the real wiring
// (jsonConnContext, forwardIdentity, jsonIncomingHeaderMatcher) and check the
// identity a handler would end up authorizing.

// daemonSideCtx is what a handler sees for a gateway-relayed call. The transport
// peer must be this process's own identity: the gateway is the daemon, so the two
// cannot differ, and hardcoding root here instead would describe a state that
// never occurs.
func daemonSideCtx(t *testing.T, md metadata.MD) context.Context {
	t.Helper()
	self, err := ipcauth.CurrentProcessIdentity()
	if err != nil {
		t.Skipf("cannot read this process's identity: %v", err)
	}
	ctx := peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: ipcauth.AuthInfo{
			CommonAuthInfo: credentials.CommonAuthInfo{SecurityLevel: credentials.NoSecurity},
			Identity:       self,
		},
	})
	return metadata.NewIncomingContext(ctx, md)
}

// gatewayMetadata reproduces what the daemon receives for a JSON request: the
// mux annotates the context from the request's headers, then the interceptor on the
// gateway's client connection stamps the caller's identity. The order matters,
// since the interceptor must win over anything a header put there.
func gatewayMetadata(t *testing.T, req *http.Request, ctx context.Context) metadata.MD {
	t.Helper()
	mux := runtime.NewServeMux(runtime.WithIncomingHeaderMatcher(jsonIncomingHeaderMatcher))
	annotated, err := runtime.AnnotateContext(ctx, mux, req,
		"/daemon.DaemonService/SetConfig",
		runtime.WithHTTPPathPattern("/daemon.DaemonService/SetConfig"))
	if err != nil {
		t.Fatalf("annotate: %v", err)
	}

	md, ok := metadata.FromOutgoingContext(forwardIdentity(annotated))
	if !ok {
		t.Fatal("the interceptor produced no metadata")
	}
	return md
}

// clientCtx is the connection context jsonConnContext would have produced for an
// HTTP client whose identity the gateway could read.
func clientCtx(id ipcauth.Identity, known bool) context.Context {
	return context.WithValue(context.Background(), jsonPeerIdentity{},
		jsonPeerIdentityValue{id: id, known: known})
}

// An HTTP client must not be able to name its own identity. grpc-gateway turns
// Grpc-Metadata-<key> headers into gRPC metadata, so without the header filter and
// the interceptor overwriting the reserved keys, this request would authorize as
// uid 0.
func TestJSONGateway_ForgedIdentityHeaderIsDropped(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "http://localhost/daemon.DaemonService/SetConfig", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Grpc-Metadata-X-Netbird-Fwd-Uid", "0")
	req.Header.Set("Grpc-Metadata-X-Netbird-Fwd-Gid", "0")
	req.Header.Set("Grpc-Metadata-X-Netbird-Fwd", "1")
	req.Header.Set("Grpc-Metadata-X-Netbird-Fwd-Sid", "S-1-5-18")

	caller := ipcauth.Identity{UID: 31000, GID: 31000}
	md := gatewayMetadata(t, req, clientCtx(caller, true))

	id, ok := ipcauth.CallerIdentity(daemonSideCtx(t, md))
	if !ok {
		t.Fatal("the forwarded identity should be usable")
	}
	if id.IsPrivileged() {
		t.Errorf("forged header was believed: authorized as %v", id)
	}
	if id.UID != caller.UID {
		t.Errorf("authorized as uid %d, want the real client %d", id.UID, caller.UID)
	}
}

// A request with no headers at all (HTTP/1.0 needs no Host, and a unix socket
// yields no host:port) makes grpc-gateway produce no metadata whatsoever and skip
// its annotators: "if len(pairs) == 0 { return ctx, nil, nil }" in
// runtime/context.go. That is why the identity is stamped by an interceptor
// instead. This is the case that previously reached the gate as the daemon itself.
func TestJSONGateway_HeaderlessRequestIsStillMarkedForwarded(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "http://localhost/daemon.DaemonService/SetConfig", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header = http.Header{}
	req.Host = ""

	caller := ipcauth.Identity{UID: 31000, GID: 31000}
	ctx := clientCtx(caller, true)

	// Pin the skip path itself: if grpc-gateway ever produced a pair here, this
	// test would still pass below while no longer covering what it was written for.
	mux := runtime.NewServeMux(runtime.WithIncomingHeaderMatcher(jsonIncomingHeaderMatcher))
	annotated, err := runtime.AnnotateContext(ctx, mux, req,
		"/daemon.DaemonService/SetConfig",
		runtime.WithHTTPPathPattern("/daemon.DaemonService/SetConfig"))
	if err != nil {
		t.Fatalf("annotate: %v", err)
	}
	if md, ok := metadata.FromOutgoingContext(annotated); ok {
		t.Fatalf("grpc-gateway produced metadata %v for a headerless request; "+
			"this test no longer covers the annotator-skip path", md)
	}

	md := gatewayMetadata(t, req, ctx)

	id, ok := ipcauth.CallerIdentity(daemonSideCtx(t, md))
	if !ok {
		t.Fatal("the forwarded identity should be usable")
	}
	if id.UID != caller.UID || id.IsPrivileged() {
		t.Errorf("authorized as %v, want the real client uid %d", id, caller.UID)
	}
}

// When the gateway cannot read its client's identity (a TCP JSON socket, say) it
// forwards the marker alone. The daemon must then report "unidentified" so the
// privileged operations refuse, rather than falling back to the gateway's own
// identity.
func TestJSONGateway_UnreadableClientIdentityIsUnidentified(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "http://localhost/daemon.DaemonService/SetConfig", nil)
	if err != nil {
		t.Fatal(err)
	}

	md := gatewayMetadata(t, req, clientCtx(ipcauth.Identity{}, false))

	if id, ok := ipcauth.CallerIdentity(daemonSideCtx(t, md)); ok {
		t.Errorf("a request with no client identity was authorized as %v", id)
	}
}

// A request that never passed through jsonConnContext (no stashed identity) must
// also come out unidentified rather than as the daemon.
func TestJSONGateway_MissingConnContextIsUnidentified(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "http://localhost/daemon.DaemonService/SetConfig", nil)
	if err != nil {
		t.Fatal(err)
	}

	md := gatewayMetadata(t, req, context.Background())

	if id, ok := ipcauth.CallerIdentity(daemonSideCtx(t, md)); ok {
		t.Errorf("a request with no connection context was authorized as %v", id)
	}
}

// End to end over a real unix socket: the gateway reads the connecting client's
// identity from the socket itself, so a client cannot present anything else.
func TestJSONGateway_IdentityComesFromTheSocket(t *testing.T) {
	mux := runtime.NewServeMux(runtime.WithIncomingHeaderMatcher(jsonIncomingHeaderMatcher))

	type observed struct {
		md metadata.MD
	}
	seen := make(chan observed, 1)

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, err := runtime.AnnotateContext(r.Context(), mux, r,
				"/daemon.DaemonService/SetConfig",
				runtime.WithHTTPPathPattern("/daemon.DaemonService/SetConfig"))
			if err != nil {
				t.Errorf("annotate: %v", err)
				return
			}
			md, _ := metadata.FromOutgoingContext(forwardIdentity(ctx))
			seen <- observed{md: md}
			w.WriteHeader(http.StatusOK)
		}),
		ReadHeaderTimeout: 5 * time.Second,
		ConnContext:       jsonConnContext,
	}

	sock := filepath.Join(t.TempDir(), "http.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := srv.Close(); err != nil {
			t.Logf("close server: %v", err)
		}
	})
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			t.Logf("serve: %v", err)
		}
	}()

	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Logf("close conn: %v", err)
		}
	})

	// Forge the identity headers on the wire as well.
	request := "POST /daemon.DaemonService/SetConfig HTTP/1.1\r\n" +
		"Host: localhost\r\n" +
		"Grpc-Metadata-X-Netbird-Fwd: 1\r\n" +
		"Grpc-Metadata-X-Netbird-Fwd-Uid: 0\r\n" +
		"Content-Length: 0\r\n\r\n"
	if _, err := conn.Write([]byte(request)); err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-seen:
		self, err := ipcauth.CurrentProcessIdentity()
		if err != nil {
			t.Skipf("cannot read this process's identity: %v", err)
		}
		// The socket peer is this test process, so that is the identity the
		// gateway must forward, not the uid 0 the request asked for.
		if uids := got.md.Get("x-netbird-fwd-uid"); len(uids) != 1 {
			t.Fatalf("x-netbird-fwd-uid = %v, want exactly the gateway's own value", uids)
		}
		id, ok := ipcauth.CallerIdentity(daemonSideCtx(t, got.md))
		if !ok {
			t.Fatal("the forwarded identity should be usable")
		}
		if id.UID != self.UID {
			t.Errorf("authorized as uid %d, want the socket peer %d", id.UID, self.UID)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the gateway never handled the request")
	}
}
