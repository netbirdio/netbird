package proxy

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/netbirdio/netbird/proxy/internal/middleware"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// stubFactory builds a stub Middleware so the registry's IsKnown check
// passes for the configured id. The translator never invokes the
// middleware, so the methods only need to satisfy the interface.
type stubFactory struct {
	id   string
	slot middleware.Slot
}

func (f stubFactory) ID() string { return f.id }
func (f stubFactory) New(_ []byte) (middleware.Middleware, error) {
	return stubMiddleware(f), nil
}

type stubMiddleware struct {
	id   string
	slot middleware.Slot
}

func (m stubMiddleware) ID() string                     { return m.id }
func (m stubMiddleware) Version() string                { return "test" }
func (m stubMiddleware) Slot() middleware.Slot          { return m.slot }
func (m stubMiddleware) AcceptedContentTypes() []string { return nil }
func (m stubMiddleware) MetadataKeys() []string         { return nil }
func (m stubMiddleware) MutationsSupported() bool       { return false }
func (m stubMiddleware) Close() error                   { return nil }
func (m stubMiddleware) Invoke(context.Context, *middleware.Input) (*middleware.Output, error) {
	panic("stubMiddleware.Invoke must not be called in translator tests")
}

// newTestRegistry returns a fresh registry pre-populated with the given
// middleware ids in the matching slot.
func newTestRegistry(t *testing.T, entries map[string]middleware.Slot) *middleware.Registry {
	t.Helper()
	r := middleware.NewRegistry()
	for id, slot := range entries {
		require.NoError(t, r.Register(stubFactory{id: id, slot: slot}), "stub registration must succeed")
	}
	return r
}

func TestTranslateMiddlewareConfigs_EmptyInput(t *testing.T) {
	assert.Nil(t, translateMiddlewareConfigs(context.Background(), "target-a", nil, nil),
		"nil input should translate to nil")
	assert.Nil(t, translateMiddlewareConfigs(context.Background(), "target-a", []*proto.MiddlewareConfig{}, nil),
		"empty input should translate to nil")
}

func TestTranslateMiddlewareConfigs_KnownIDs(t *testing.T) {
	registry := newTestRegistry(t, map[string]middleware.Slot{
		"llm_request_parser":  middleware.SlotOnRequest,
		"llm_response_parser": middleware.SlotOnResponse,
	})
	in := []*proto.MiddlewareConfig{
		{
			Id:         "llm_request_parser",
			Enabled:    true,
			Slot:       proto.MiddlewareSlot_MIDDLEWARE_SLOT_ON_REQUEST,
			ConfigJson: []byte(`{"foo":"bar"}`),
			FailMode:   proto.MiddlewareConfig_FAIL_OPEN,
			Timeout:    durationpb.New(250 * time.Millisecond),
			CanMutate:  true,
		},
		{
			Id:         "llm_response_parser",
			Enabled:    false,
			Slot:       proto.MiddlewareSlot_MIDDLEWARE_SLOT_ON_RESPONSE,
			ConfigJson: nil,
			FailMode:   proto.MiddlewareConfig_FAIL_CLOSED,
			Timeout:    durationpb.New(50 * time.Millisecond),
		},
	}

	out := translateMiddlewareConfigs(context.Background(), "target-a", in, registry)
	require.Len(t, out, 2, "two known middlewares should produce two specs")

	assert.Equal(t, "llm_request_parser", out[0].ID, "first id should match")
	assert.Equal(t, middleware.SlotOnRequest, out[0].Slot, "first slot should be on_request")
	assert.True(t, out[0].Enabled, "first spec should be enabled")
	assert.Equal(t, middleware.FailOpen, out[0].FailMode, "first spec should be fail-open")
	assert.Equal(t, 250*time.Millisecond, out[0].Timeout, "first spec timeout should pass through")
	assert.True(t, out[0].CanMutate, "first spec should permit mutations")
	assert.Equal(t, []byte(`{"foo":"bar"}`), out[0].RawConfig, "first spec raw config should match")

	assert.Equal(t, "llm_response_parser", out[1].ID, "second id should match")
	assert.Equal(t, middleware.SlotOnResponse, out[1].Slot, "second slot should be on_response")
	assert.False(t, out[1].Enabled, "second spec should be disabled")
	assert.Equal(t, middleware.FailClosed, out[1].FailMode, "second spec should be fail-closed")
	assert.Equal(t, 50*time.Millisecond, out[1].Timeout, "second spec timeout should pass through")
	assert.Nil(t, out[1].RawConfig, "second spec raw config should be nil")
}

func TestTranslateMiddlewareConfigs_UnknownIDSkipped(t *testing.T) {
	registry := newTestRegistry(t, map[string]middleware.Slot{
		"llm_request_parser": middleware.SlotOnRequest,
	})
	in := []*proto.MiddlewareConfig{
		{Id: "llm_request_parser", Slot: proto.MiddlewareSlot_MIDDLEWARE_SLOT_ON_REQUEST},
		{Id: "not_registered", Slot: proto.MiddlewareSlot_MIDDLEWARE_SLOT_ON_REQUEST},
	}
	out := translateMiddlewareConfigs(context.Background(), "target-unknown", in, registry)
	require.Len(t, out, 1, "unknown id must be skipped")
	assert.Equal(t, "llm_request_parser", out[0].ID, "remaining entry should be the known one")
}

func TestTranslateMiddlewareConfigs_NilRegistrySkipsValidation(t *testing.T) {
	in := []*proto.MiddlewareConfig{
		{Id: "anything_goes", Slot: proto.MiddlewareSlot_MIDDLEWARE_SLOT_ON_REQUEST},
	}
	out := translateMiddlewareConfigs(context.Background(), "target-nilreg", in, nil)
	require.Len(t, out, 1, "nil registry must accept any non-empty id")
	assert.Equal(t, "anything_goes", out[0].ID, "id should pass through unchecked")
}

func TestTranslateMiddlewareConfigs_TimeoutClamps(t *testing.T) {
	registry := newTestRegistry(t, map[string]middleware.Slot{
		"llm_request_parser": middleware.SlotOnRequest,
	})
	in := []*proto.MiddlewareConfig{
		{Id: "llm_request_parser", Slot: proto.MiddlewareSlot_MIDDLEWARE_SLOT_ON_REQUEST, Timeout: nil},
		{Id: "llm_request_parser", Slot: proto.MiddlewareSlot_MIDDLEWARE_SLOT_ON_REQUEST, Timeout: durationpb.New(time.Microsecond)},
		{Id: "llm_request_parser", Slot: proto.MiddlewareSlot_MIDDLEWARE_SLOT_ON_REQUEST, Timeout: durationpb.New(time.Hour)},
	}
	out := translateMiddlewareConfigs(context.Background(), "target-clamp", in, registry)
	require.Len(t, out, 3, "clamping must keep all three entries")
	assert.Equal(t, middleware.DefaultTimeout, out[0].Timeout, "zero timeout should default")
	assert.Equal(t, middleware.MinTimeout, out[1].Timeout, "below-min timeout should clamp up")
	assert.Equal(t, middleware.MaxTimeout, out[2].Timeout, "above-max timeout should clamp down")
}

func TestTranslateMiddlewareConfigs_FailModeMapping(t *testing.T) {
	registry := newTestRegistry(t, map[string]middleware.Slot{
		"llm_request_parser": middleware.SlotOnRequest,
	})
	in := []*proto.MiddlewareConfig{
		{Id: "llm_request_parser", Slot: proto.MiddlewareSlot_MIDDLEWARE_SLOT_ON_REQUEST},
		{Id: "llm_request_parser", Slot: proto.MiddlewareSlot_MIDDLEWARE_SLOT_ON_REQUEST, FailMode: proto.MiddlewareConfig_FAIL_CLOSED},
	}
	out := translateMiddlewareConfigs(context.Background(), "target-failmode", in, registry)
	require.Len(t, out, 2, "both entries should translate")
	assert.Equal(t, middleware.FailOpen, out[0].FailMode, "default fail mode should be open")
	assert.Equal(t, middleware.FailClosed, out[1].FailMode, "explicit fail closed should map")
}

func TestTranslateMiddlewareConfigs_SlotMapping(t *testing.T) {
	registry := newTestRegistry(t, map[string]middleware.Slot{
		"req":  middleware.SlotOnRequest,
		"resp": middleware.SlotOnResponse,
		"term": middleware.SlotTerminal,
	})
	in := []*proto.MiddlewareConfig{
		{Id: "req", Slot: proto.MiddlewareSlot_MIDDLEWARE_SLOT_ON_REQUEST},
		{Id: "resp", Slot: proto.MiddlewareSlot_MIDDLEWARE_SLOT_ON_RESPONSE},
		{Id: "term", Slot: proto.MiddlewareSlot_MIDDLEWARE_SLOT_TERMINAL},
		{Id: "req", Slot: proto.MiddlewareSlot_MIDDLEWARE_SLOT_UNSPECIFIED},
	}
	out := translateMiddlewareConfigs(context.Background(), "target-slot", in, registry)
	require.Len(t, out, 3, "unspecified slot entry must be skipped")
	assert.Equal(t, middleware.SlotOnRequest, out[0].Slot, "on_request slot mapping")
	assert.Equal(t, middleware.SlotOnResponse, out[1].Slot, "on_response slot mapping")
	assert.Equal(t, middleware.SlotTerminal, out[2].Slot, "terminal slot mapping")
}

func TestTranslateMiddlewareConfigs_EmptyIDSkipped(t *testing.T) {
	registry := newTestRegistry(t, map[string]middleware.Slot{
		"llm_request_parser": middleware.SlotOnRequest,
	})
	in := []*proto.MiddlewareConfig{
		{Id: "", Slot: proto.MiddlewareSlot_MIDDLEWARE_SLOT_ON_REQUEST},
		{Id: "llm_request_parser", Slot: proto.MiddlewareSlot_MIDDLEWARE_SLOT_ON_REQUEST},
	}
	out := translateMiddlewareConfigs(context.Background(), "target-empty-id", in, registry)
	require.Len(t, out, 1, "empty id must be dropped")
	assert.Equal(t, "llm_request_parser", out[0].ID, "remaining entry should be valid")
}

// TestTranslateMiddlewareConfigs_TruncatesAboveCap proves the translator
// truncates lists that exceed MaxMiddlewaresPerChain rather than dropping
// the whole slice, matching the documented G3 behaviour.
func TestTranslateMiddlewareConfigs_TruncatesAboveCap(t *testing.T) {
	registry := newTestRegistry(t, map[string]middleware.Slot{
		"llm_request_parser": middleware.SlotOnRequest,
	})
	overCap := middleware.MaxMiddlewaresPerChain + 1
	in := make([]*proto.MiddlewareConfig, 0, overCap)
	for i := 0; i < overCap; i++ {
		in = append(in, &proto.MiddlewareConfig{
			Id:   "llm_request_parser",
			Slot: proto.MiddlewareSlot_MIDDLEWARE_SLOT_ON_REQUEST,
		})
	}
	out := translateMiddlewareConfigs(context.Background(), "target-truncate", in, registry)
	assert.Len(t, out, middleware.MaxMiddlewaresPerChain, "over-cap input must be truncated to MaxMiddlewaresPerChain")
}

func TestTranslateMiddlewareConfigs_AllowsListAtCap(t *testing.T) {
	registry := newTestRegistry(t, map[string]middleware.Slot{
		"llm_request_parser": middleware.SlotOnRequest,
	})
	in := make([]*proto.MiddlewareConfig, 0, middleware.MaxMiddlewaresPerChain)
	for i := 0; i < middleware.MaxMiddlewaresPerChain; i++ {
		in = append(in, &proto.MiddlewareConfig{
			Id:   "llm_request_parser",
			Slot: proto.MiddlewareSlot_MIDDLEWARE_SLOT_ON_REQUEST,
		})
	}
	out := translateMiddlewareConfigs(context.Background(), "target-cap", in, registry)
	assert.Len(t, out, middleware.MaxMiddlewaresPerChain, "list at the cap boundary must translate fully")
}

func TestProtoToMiddlewareSlot(t *testing.T) {
	cases := []struct {
		name   string
		in     proto.MiddlewareSlot
		want   middleware.Slot
		wantOk bool
	}{
		{"unspecified", proto.MiddlewareSlot_MIDDLEWARE_SLOT_UNSPECIFIED, 0, false},
		{"on_request", proto.MiddlewareSlot_MIDDLEWARE_SLOT_ON_REQUEST, middleware.SlotOnRequest, true},
		{"on_response", proto.MiddlewareSlot_MIDDLEWARE_SLOT_ON_RESPONSE, middleware.SlotOnResponse, true},
		{"terminal", proto.MiddlewareSlot_MIDDLEWARE_SLOT_TERMINAL, middleware.SlotTerminal, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := protoToMiddlewareSlot(tc.in)
			assert.Equal(t, tc.wantOk, ok, "ok flag for %s", tc.name)
			if tc.wantOk {
				assert.Equal(t, tc.want, got, "slot mapping for %s", tc.name)
			}
		})
	}
}
