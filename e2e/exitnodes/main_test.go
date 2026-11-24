//go:build e2e

// Package exitnodes holds the container-based e2e suite for exit nodes. One combined
// server and one topology are shared by the package:
//
//   - an HTTP target alone on an internal Docker network, standing in for the
//     internet: a peer can reach it only through an exit node;
//   - the exit peer, attached to that network with forwarding enabled;
//   - alice in group A and bob in group B, the peers whose access the tests change.
//
// Each test creates its own exit node and policies, under names no earlier test
// used, and removes them when it ends.
package exitnodes

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/netbirdio/netbird/e2e/harness"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

const (
	exitPeerName = "exit"
	aliceName    = "alice"
	bobName      = "bob"
)

// srv is the shared combined server, PAT-authenticated by the time any test runs.
var srv *harness.Combined

// env is the shared topology.
var env *topology

type topology struct {
	target *harness.IsolatedTarget

	exit, alice, bob *harness.Client
	// exitPeerID is the exit peer's management ID; exitPeerTargetIP is its address
	// on the target's network, the source the target sees for forwarded traffic.
	exitPeerID       string
	exitPeerTargetIP string

	groupA, groupB string
	alicePeerID    string
	bobPeerID      string
}

func TestMain(m *testing.M) {
	os.Exit(run(m))
}

func run(m *testing.M) int {
	// Generous timeout to cover a cold image build on first run.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	var err error
	srv, err = harness.StartCombined(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "e2e: start combined server: %v\n", err)
		return 1
	}
	defer func() { _ = srv.Terminate(context.Background()) }()

	if _, err := srv.Bootstrap(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "e2e: bootstrap admin PAT: %v\n", err)
		return 1
	}

	env = &topology{}
	defer env.terminate()
	if err := env.start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "e2e: start topology: %v\n", err)
		env.dumpLogs(context.Background())
		return 1
	}

	code := m.Run()
	if code != 0 {
		env.dumpLogs(context.Background())
	}
	return code
}

func (e *topology) start(ctx context.Context) error {
	var err error
	if e.target, err = harness.StartIsolatedTarget(ctx); err != nil {
		return err
	}

	exitGroup, err := createGroup(ctx, "exit-peers")
	if err != nil {
		return err
	}
	if e.groupA, err = createGroup(ctx, "group-a"); err != nil {
		return err
	}
	if e.groupB, err = createGroup(ctx, "group-b"); err != nil {
		return err
	}

	if e.exit, e.exitPeerID, err = startPeer(ctx, exitPeerName, exitGroup,
		harness.WithExtraNetworks(e.target.NetworkName()), harness.WithIPForwarding()); err != nil {
		return err
	}
	if e.exitPeerTargetIP, err = e.exit.NetworkIP(ctx, e.target.NetworkName()); err != nil {
		return err
	}
	if e.alice, e.alicePeerID, err = startPeer(ctx, aliceName, e.groupA); err != nil {
		return err
	}
	if e.bob, e.bobPeerID, err = startPeer(ctx, bobName, e.groupB); err != nil {
		return err
	}
	return nil
}

func createGroup(ctx context.Context, name string) (string, error) {
	grp, err := srv.API().Groups.Create(ctx, api.PostApiGroupsJSONRequestBody{Name: name})
	if err != nil {
		return "", fmt.Errorf("create group %s: %w", name, err)
	}
	return grp.Id, nil
}

// startPeer joins a client to the account in the given group and returns it with its
// management peer ID.
func startPeer(ctx context.Context, name, groupID string, opts ...harness.ClientOption) (*harness.Client, string, error) {
	key, err := srv.API().SetupKeys.Create(ctx, api.PostApiSetupKeysJSONRequestBody{
		Name:       "e2e-" + name,
		Type:       "one-off",
		ExpiresIn:  86400,
		AutoGroups: []string{groupID},
	})
	if err != nil {
		return nil, "", fmt.Errorf("create setup key for %s: %w", name, err)
	}

	cl, err := harness.StartClient(ctx, srv, key.Key, append(opts, harness.WithClientName(name))...)
	if err != nil {
		return nil, "", fmt.Errorf("start client %s: %w", name, err)
	}
	if err := cl.WaitConnected(ctx, 90*time.Second); err != nil {
		return cl, "", fmt.Errorf("client %s: %w", name, err)
	}

	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		peers, err := srv.API().Peers.List(ctx)
		if err == nil {
			for _, p := range peers {
				if p.Hostname == name {
					return cl, p.Id, nil
				}
			}
		}
		time.Sleep(2 * time.Second)
	}
	return cl, "", fmt.Errorf("peer %s did not register with management", name)
}

func (e *topology) dumpLogs(ctx context.Context) {
	for name, cl := range map[string]*harness.Client{exitPeerName: e.exit, aliceName: e.alice, bobName: e.bob} {
		if cl != nil {
			fmt.Fprintf(os.Stderr, "==== %s client logs ====\n%s\n", name, cl.Logs(ctx))
		}
	}
	fmt.Fprintf(os.Stderr, "==== combined server logs ====\n%s\n", srv.Logs(ctx))
}

func (e *topology) terminate() {
	ctx := context.Background()
	for _, cl := range []*harness.Client{e.alice, e.bob, e.exit} {
		if cl != nil {
			_ = cl.Terminate(ctx)
		}
	}
	if e.target != nil {
		_ = e.target.Terminate(ctx)
	}
}
