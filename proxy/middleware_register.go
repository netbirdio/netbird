package proxy

// Anonymous imports trigger init() in each built-in middleware
// sub-package so they self-register into mwbuiltin.DefaultRegistry()
// before initMiddlewareManager builds the resolver. Add a new line
// here when introducing another built-in middleware.
import (
	_ "github.com/netbirdio/netbird/proxy/internal/middleware/builtin/cost_meter"
	_ "github.com/netbirdio/netbird/proxy/internal/middleware/builtin/llm_guardrail"
	_ "github.com/netbirdio/netbird/proxy/internal/middleware/builtin/llm_identity_inject"
	_ "github.com/netbirdio/netbird/proxy/internal/middleware/builtin/llm_limit_check"
	_ "github.com/netbirdio/netbird/proxy/internal/middleware/builtin/llm_limit_record"
	_ "github.com/netbirdio/netbird/proxy/internal/middleware/builtin/llm_request_parser"
	_ "github.com/netbirdio/netbird/proxy/internal/middleware/builtin/llm_response_parser"
	_ "github.com/netbirdio/netbird/proxy/internal/middleware/builtin/llm_router"
)
