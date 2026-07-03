// Package builtin holds the package-level middleware registry that
// concrete middleware packages register themselves into via init().
// Server boot anonymous-imports each middleware sub-package; the
// resolver attached to the middleware Manager pulls factories out of
// this registry.
package builtin

import (
	"context"
	"sync"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/metric"
	"google.golang.org/grpc"

	"github.com/netbirdio/netbird/proxy/internal/middleware"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// MgmtClient is the narrow slice of proto.ProxyServiceClient that
// builtin middlewares may use during request / response handling.
// Only the agent-network limit pair (llm_limit_check + llm_limit_record)
// uses this today; declaring the surface here keeps the dependency
// explicit at boot time.
//
// proto.ProxyServiceClient already satisfies this interface so server
// boot just forwards its existing client.
type MgmtClient interface {
	CheckLLMPolicyLimits(ctx context.Context, in *proto.CheckLLMPolicyLimitsRequest, opts ...grpc.CallOption) (*proto.CheckLLMPolicyLimitsResponse, error)
	RecordLLMUsage(ctx context.Context, in *proto.RecordLLMUsageRequest, opts ...grpc.CallOption) (*proto.RecordLLMUsageResponse, error)
}

// defaultRegistry is the package-level registry that concrete builtin
// middlewares register themselves into via init().
var defaultRegistry = middleware.NewRegistry()

// FactoryContext is the per-process bag that concrete factories may
// consult during construction. It carries the proxy-lifetime context,
// the data directory used for static config files (pricing tables,
// allowlists), the OTel meter, and the proxy logger.
//
// Configure must be called once at boot before any chain build calls
// Resolve. Calling it twice overwrites the prior value; tests may rely
// on this to reset state.
type FactoryContext struct {
	Context    context.Context
	DataDir    string
	Meter      metric.Meter
	Logger     *log.Logger
	MgmtClient MgmtClient
}

var (
	ctxStore FactoryContext
	ctxMu    sync.RWMutex
)

// Configure stores the per-process FactoryContext. Concrete factories
// reach for it via Context(). mgmt may be nil on tests / standalone
// builds with no management server; consumers must guard.
func Configure(ctx context.Context, dataDir string, meter metric.Meter, logger *log.Logger, mgmt MgmtClient) {
	ctxMu.Lock()
	defer ctxMu.Unlock()
	ctxStore = FactoryContext{
		Context:    ctx,
		DataDir:    dataDir,
		Meter:      meter,
		Logger:     logger,
		MgmtClient: mgmt,
	}
}

// Context returns the stored FactoryContext. Returns a zero value when
// Configure was never called; consumers must guard against nil
// Context/Meter/Logger if they care.
func Context() FactoryContext {
	ctxMu.RLock()
	defer ctxMu.RUnlock()
	return ctxStore
}

// Register adds a factory to the default registry. Called from init()
// blocks of concrete middleware packages. Panics on collision so
// duplicate IDs surface at startup.
func Register(f middleware.Factory) {
	defaultRegistry.MustRegister(f)
}

// DefaultRegistry returns the shared registry. The proxy server
// constructs the Resolver from it at boot.
func DefaultRegistry() *middleware.Registry {
	return defaultRegistry
}
