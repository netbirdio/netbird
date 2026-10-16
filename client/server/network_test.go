package server

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/routemanager"
	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/route"
)

func TestSelectionApplied(t *testing.T) {
	tests := map[string]struct {
		err  error
		want bool
	}{
		"nil error":                  {err: nil, want: true},
		"unrelated error":            {err: errors.New("boom"), want: true},
		"wrapped ErrNoRoutesApplied": {err: fmt.Errorf("select routes: %w", routemanager.ErrNoRoutesApplied), want: false},
		"bare ErrNoRoutesApplied":    {err: routemanager.ErrNoRoutesApplied, want: false},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tt.want, selectionApplied(tt.err), "selectionApplied(%v) mismatch", tt.err)
		})
	}
}

func newNetworkSelectionManager(t *testing.T, recorder *peer.Status) *routemanager.DefaultManager {
	t.Helper()
	// Disabled system routing uses the production no-op route counter. No peers are
	// connected, so selection cannot write allowed IPs to an interface either.
	manager := routemanager.NewManager(routemanager.ManagerConfig{
		Context:             context.Background(),
		StatusRecorder:      recorder,
		DisableClientRoutes: true,
		DisableServerRoutes: true,
	})
	t.Cleanup(func() { manager.Stop(nil) })
	require.NoError(t, manager.Init())

	routes := make(route.HAMap)
	for id, prefix := range map[route.NetID]string{
		"lan":    "192.0.2.0/24",
		"office": "198.51.100.0/24",
	} {
		r := &route.Route{ID: route.ID(id), NetID: id, Network: netip.MustParsePrefix(prefix), Peer: "offline-peer"}
		routes[r.GetHAUniqueID()] = []*route.Route{r}
	}
	require.NoError(t, manager.UpdateRoutes(1, nil, routes, false))
	return manager
}

func TestNetworkSelection(t *testing.T) {
	tests := []struct {
		name      string
		deselect  bool
		initial   []route.NetID
		request   *proto.SelectNetworksRequest
		selected  []route.NetID
		wantError bool
		applied   bool
	}{
		{
			name: "select replaces selection", initial: []route.NetID{"office"},
			request:  &proto.SelectNetworksRequest{NetworkIDs: []string{"lan"}},
			selected: []route.NetID{"lan"}, applied: true,
		},
		{
			name: "select appends to selection", initial: []route.NetID{"office"},
			request:  &proto.SelectNetworksRequest{NetworkIDs: []string{"lan"}, Append: true},
			selected: []route.NetID{"lan", "office"}, applied: true,
		},
		{
			name: "select partial failure with unknown first", initial: []route.NetID{"office"},
			request:  &proto.SelectNetworksRequest{NetworkIDs: []string{"missing", "lan"}},
			selected: []route.NetID{"lan"}, wantError: true, applied: true,
		},
		{
			name: "select partial failure with unknown last", initial: []route.NetID{"office"},
			request:  &proto.SelectNetworksRequest{NetworkIDs: []string{"lan", "missing"}, Append: true},
			selected: []route.NetID{"lan", "office"}, wantError: true, applied: true,
		},
		{
			name: "select all unknown preserves selection", initial: []route.NetID{"office"},
			request:  &proto.SelectNetworksRequest{NetworkIDs: []string{"missing"}},
			selected: []route.NetID{"office"}, wantError: true,
		},
		{
			name: "select all", initial: []route.NetID{"lan"},
			request:  &proto.SelectNetworksRequest{All: true},
			selected: []route.NetID{"lan", "office"}, applied: true,
		},
		{
			name: "empty selection deselects all", initial: []route.NetID{"lan", "office"},
			request: &proto.SelectNetworksRequest{}, applied: true,
		},
		{
			name: "deselect known network", deselect: true, initial: []route.NetID{"lan", "office"},
			request:  &proto.SelectNetworksRequest{NetworkIDs: []string{"lan"}},
			selected: []route.NetID{"office"}, applied: true,
		},
		{
			name: "deselect partial failure with unknown first", deselect: true, initial: []route.NetID{"lan", "office"},
			request:  &proto.SelectNetworksRequest{NetworkIDs: []string{"missing", "lan"}},
			selected: []route.NetID{"office"}, wantError: true, applied: true,
		},
		{
			name: "deselect partial failure with unknown last", deselect: true, initial: []route.NetID{"lan", "office"},
			request:  &proto.SelectNetworksRequest{NetworkIDs: []string{"lan", "missing"}},
			selected: []route.NetID{"office"}, wantError: true, applied: true,
		},
		{
			name: "deselect all unknown preserves selection", deselect: true, initial: []route.NetID{"lan", "office"},
			request:  &proto.SelectNetworksRequest{NetworkIDs: []string{"missing"}},
			selected: []route.NetID{"lan", "office"}, wantError: true,
		},
		{
			name: "deselect all", deselect: true, initial: []route.NetID{"lan", "office"},
			request: &proto.SelectNetworksRequest{All: true}, applied: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestServer()
			manager := newNetworkSelectionManager(t, s.statusRecorder)
			require.NoError(t, manager.GetRouteSelector().SelectRoutes(tt.initial, false, []route.NetID{"lan", "office"}))

			change := s.selectNetworks
			title := "Network selection changed"
			originalError := "1 error occurred:\n\t* select routes: 1 error occurred:\n\t* route 'missing' is not available"
			if tt.deselect {
				change = s.deselectNetworks
				title = "Network deselection changed"
				originalError = "deselect routes: 1 error occurred:\n\t* route 'missing' is not available"
			}
			response, err := change(tt.request, manager)
			if tt.wantError {
				assert.EqualError(t, err, originalError, "the RPC must preserve the route manager's error text")
				assert.Nil(t, response, "a failed RPC must not return a success response")
				assert.Equal(t, !tt.applied, errors.Is(err, routemanager.ErrNoRoutesApplied), "only an all-unknown request applies nothing")
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, response, "a successful RPC must return a response")
			}

			var selected []route.NetID
			for id := range manager.GetSelectedClientRoutes() {
				selected = append(selected, id.NetID())
			}
			assert.ElementsMatch(t, tt.selected, selected, "the valid part of the request must be applied")
			events := s.statusRecorder.GetEventHistory()
			if !tt.applied {
				assert.Empty(t, events, "an all-unknown request must not publish a selection event")
				return
			}
			require.Len(t, events, 1, "an applied request must publish exactly one selection event")
			event := events[0]
			assert.Equal(t, proto.SystemEvent_INFO, event.GetSeverity(), "event severity should be INFO")
			assert.Equal(t, proto.SystemEvent_SYSTEM, event.GetCategory(), "event category should be SYSTEM")
			assert.Equal(t, title, event.GetMessage(), "event title must identify the operation")
			assert.Equal(t, map[string]string{
				"networks": strings.Join(tt.request.GetNetworkIDs(), ", "),
				"append":   fmt.Sprint(tt.request.GetAppend()),
				"all":      fmt.Sprint(tt.request.GetAll()),
			}, event.GetMetadata(), "event metadata must retain the complete request, including unavailable IDs")
		})
	}
}

func TestNetworkSelectionUnavailable(t *testing.T) {
	for _, deselect := range []bool{false, true} {
		for _, state := range []string{"disabled", "disconnected", "engine not initialized"} {
			name := fmt.Sprintf("deselect=%t/%s", deselect, state)
			t.Run(name, func(t *testing.T) {
				s := newTestServer()
				s.networksDisabled = state == "disabled"
				if state == "engine not initialized" {
					s.connectClient = newDummyConnectClient(context.Background())
					t.Cleanup(func() { require.NoError(t, s.connectClient.Stop()) })
				}
				change := s.SelectNetworks
				if deselect {
					change = s.DeselectNetworks
				}

				response, err := change(context.Background(), &proto.SelectNetworksRequest{All: true})

				if state == "disabled" {
					assert.Equal(t, codes.Unavailable, gstatus.Code(err), "disabled networks must reject the RPC")
				} else {
					assert.EqualError(t, err, "not connected")
				}
				assert.Nil(t, response, "an unavailable RPC must not return a success response")
				assert.Empty(t, s.statusRecorder.GetEventHistory(), "a rejected RPC must not publish an event")
			})
		}
	}
}
