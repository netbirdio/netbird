package builtin_test

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"

	mwbuiltin "github.com/netbirdio/netbird/proxy/internal/middleware/builtin"

	_ "github.com/netbirdio/netbird/proxy/internal/middleware/builtin/cost_meter"
	_ "github.com/netbirdio/netbird/proxy/internal/middleware/builtin/llm_guardrail"
	_ "github.com/netbirdio/netbird/proxy/internal/middleware/builtin/llm_identity_inject"
	_ "github.com/netbirdio/netbird/proxy/internal/middleware/builtin/llm_limit_check"
	_ "github.com/netbirdio/netbird/proxy/internal/middleware/builtin/llm_limit_record"
	_ "github.com/netbirdio/netbird/proxy/internal/middleware/builtin/llm_request_parser"
	_ "github.com/netbirdio/netbird/proxy/internal/middleware/builtin/llm_response_parser"
	_ "github.com/netbirdio/netbird/proxy/internal/middleware/builtin/llm_router"
)

// TestDefaultRegistry_BuiltinIDs locks the set of middleware IDs that
// the default builtin registry exposes once every sub-package's init()
// has run. The list is the source of truth wired by the synthesiser
// in management; adding a new built-in middleware should consciously
// extend this list.
func TestDefaultRegistry_BuiltinIDs(t *testing.T) {
	got := mwbuiltin.DefaultRegistry().IDs()
	sort.Strings(got)
	want := []string{
		"cost_meter",
		"llm_guardrail",
		"llm_identity_inject",
		"llm_limit_check",
		"llm_limit_record",
		"llm_request_parser",
		"llm_response_parser",
		"llm_router",
	}
	assert.Equal(t, want, got, "default registry must expose every built-in middleware after anonymous imports")
}
