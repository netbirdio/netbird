package server

import (
	"net/http"
	"net/netip"
	"strings"

	"google.golang.org/grpc"

	"github.com/netbirdio/netbird/util/wsproxy"
)

// MultiplexHandler creates an HTTP handler that multiplexes between gRPC, WebSocket proxy, and other HTTP traffic.
func MultiplexHandler(grpcServer *grpc.Server, localGRPCAddr netip.AddrPort) http.Handler {
	proxy := New(localGRPCAddr)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == wsproxy.ProxyPath {
			proxy.Handler().ServeHTTP(w, r)
			return
		}

		grpcHeader := strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc") ||
			strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc+proto")

		if r.ProtoMajor == 2 && grpcHeader {
			grpcServer.ServeHTTP(w, r)
			return
		}
		http.NotFound(w, r)
	})
}

// AddToHTTPMux adds the WebSocket proxy handler to an existing HTTP ServeMux.
func AddToHTTPMux(mux *http.ServeMux, localGRPCAddr netip.AddrPort) {
	proxy := New(localGRPCAddr)
	mux.Handle(wsproxy.ProxyPath, proxy.Handler())
}
