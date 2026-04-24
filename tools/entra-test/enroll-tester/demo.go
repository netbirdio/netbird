package main

import (
	"context"
	"net/http/httptest"

	"github.com/gorilla/mux"

	entrajoin "github.com/netbirdio/netbird/management/server/http/handlers/entra_join"
	ed "github.com/netbirdio/netbird/management/server/integrations/entra_device"
	"github.com/netbirdio/netbird/management/server/types"
)

const (
	demoTenantID  = "demo-tenant-00000000-0000-0000-0000-000000000000"
	demoAccountID = "demo-account"
	demoAutoGroup = "nb-demo-group"
)

// runInProcessServer starts a self-contained httptest.Server running the real
// entra_join handler. It seeds an EntraDeviceAuth row + a wildcard mapping so
// any device the tester signs for will enrol successfully. Graph calls are
// intercepted by a fake that always returns accountEnabled=true.
//
// Returns the base URL plus a cleanup closure to shut the server down.
func runInProcessServer() (string, func()) {
	store := ed.NewMemoryStore()
	ctx := context.Background()

	// Seed integration.
	auth := types.NewEntraDeviceAuth(demoAccountID)
	auth.TenantID = demoTenantID
	auth.ClientID = "demo-client"
	auth.ClientSecret = "demo-secret"
	auth.Enabled = true
	_ = store.SaveEntraDeviceAuth(ctx, auth)

	// Wildcard mapping: any device in the tenant matches.
	mp := types.NewEntraDeviceAuthMapping(demoAccountID, auth.ID, "demo-wildcard",
		types.EntraGroupWildcard, []string{demoAutoGroup})
	mp.Priority = 10
	mp.AllowExtraDNSLabels = true
	_ = store.SaveEntraDeviceMapping(ctx, mp)

	mgr := ed.NewManager(store)
	mgr.PeerEnroller = &demoPeerEnroller{}
	mgr.NewGraph = func(_, _, _ string) ed.GraphClient { return &demoGraph{} }

	router := mux.NewRouter()
	entrajoin.NewHandler(mgr).Register(router)
	srv := httptest.NewServer(router)
	return srv.URL, srv.Close
}

// demoGraph is a canned GraphClient: always returns the "happy path".
type demoGraph struct{}

func (demoGraph) Device(context.Context, string) (*ed.GraphDevice, error) {
	return &ed.GraphDevice{
		ID:             "demo-entra-object-id",
		DeviceID:       "demo-device",
		AccountEnabled: true,
		DisplayName:    "demo laptop",
	}, nil
}

func (demoGraph) TransitiveMemberOf(context.Context, string) ([]string, error) {
	// Device is in a single group the wildcard mapping will match anyway.
	return []string{"demo-entra-group"}, nil
}

func (demoGraph) IsCompliant(context.Context, string) (bool, error) { return true, nil }

// demoPeerEnroller produces a deterministic fake peer id so the demo output
// is predictable.
type demoPeerEnroller struct{}

func (demoPeerEnroller) EnrollEntraDevicePeer(_ context.Context, in ed.EnrollPeerInput) (*ed.EnrollPeerResult, error) {
	return &ed.EnrollPeerResult{
		PeerID: "demo-peer-" + in.EntraDeviceID,
		NetbirdConfig: map[string]any{
			"dns_domain": "entra.demo.local",
		},
		PeerConfig: map[string]any{
			"address":   "***********",
			"dns_label": "demo-device",
		},
	}, nil
}
