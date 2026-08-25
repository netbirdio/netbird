package server

import (
	"context"

	"google.golang.org/grpc"
)

// GRPCExtension bundles an external module's contribution to the management
// gRPC server: the registration of one or more services onto the shared
// grpc.Server, any server-wide interceptors those services require, and an
// optional shutdown hook. It is a generic extension point with no knowledge of
// any specific service.
type GRPCExtension struct {
	// Register is invoked with the shared grpc.Server (as a ServiceRegistrar)
	// after the built-in services are registered. It may register any number of
	// services. May be nil.
	Register func(grpc.ServiceRegistrar)
	// UnaryInterceptors are appended to the server's unary interceptor chain,
	// running after the built-in interceptors. May be empty.
	UnaryInterceptors []grpc.UnaryServerInterceptor
	// StreamInterceptors are appended to the server's stream interceptor chain,
	// running after the built-in interceptors. May be empty.
	StreamInterceptors []grpc.StreamServerInterceptor
	// Shutdown, if non-nil, is called once during Stop() with the context
	// governing server shutdown, which carries a deadline. The hook MUST
	// return promptly and MUST abandon its work once that context is
	// cancelled or expires: it runs before the rest of Stop()'s cleanup
	// (store, event store, embedded IdP) and before Stop() itself checks the
	// context's deadline, so a hook that ignores the context will delay all
	// of that cleanup and prevent Stop() from returning on time. May be nil.
	Shutdown func(ctx context.Context)
}

// RegisterGRPCExtension registers a gRPC extension. Call before the gRPC server
// is first built (i.e. before Start); registrations after that have no effect.
func (s *BaseServer) RegisterGRPCExtension(ext GRPCExtension) {
	s.grpcExtensions = append(s.grpcExtensions, ext)
}

// appendExtensionInterceptors appends each extension's interceptors to the gRPC
// server options as additional chained interceptors. grpc.ChainUnaryInterceptor
// and grpc.ChainStreamInterceptor are additive, so the returned options run the
// extension interceptors after any interceptors already present in opts.
func appendExtensionInterceptors(opts []grpc.ServerOption, exts []GRPCExtension) []grpc.ServerOption {
	for _, ext := range exts {
		if len(ext.UnaryInterceptors) > 0 {
			opts = append(opts, grpc.ChainUnaryInterceptor(ext.UnaryInterceptors...))
		}
		if len(ext.StreamInterceptors) > 0 {
			opts = append(opts, grpc.ChainStreamInterceptor(ext.StreamInterceptors...))
		}
	}
	return opts
}

// registerExtensions registers each extension's services onto reg.
func registerExtensions(reg grpc.ServiceRegistrar, exts []GRPCExtension) {
	for _, ext := range exts {
		if ext.Register != nil {
			ext.Register(reg)
		}
	}
}

// runExtensionShutdownHooks calls each extension's shutdown hook, if set,
// passing ctx through so hooks can honor its deadline/cancellation.
func runExtensionShutdownHooks(ctx context.Context, exts []GRPCExtension) {
	for _, ext := range exts {
		if ext.Shutdown != nil {
			ext.Shutdown(ctx)
		}
	}
}
