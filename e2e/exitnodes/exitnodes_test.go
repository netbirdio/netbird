//go:build e2e

package exitnodes

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/e2e/harness"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

const (
	// propagationTimeout bounds how long a change takes to reach the peers: the
	// network map update, the route change on the client, and the tunnel to the
	// exit peer.
	propagationTimeout = 90 * time.Second
	pollInterval       = 2 * time.Second
	// denyWindow is how long a peer must keep failing to reach the target, once a
	// peer that has access reaches it, to count as denied rather than not yet
	// updated.
	denyWindow = 15 * time.Second
)

// TestExitNode_RoutesPolicySourcesThroughExitPeer checks the basic path: the policy's
// source peers reach the internet through the exit peer, and no one else does.
func TestExitNode_RoutesPolicySourcesThroughExitPeer(t *testing.T) {
	node := createExitNode(t, "en-basic", true)
	createPolicy(t, "en-basic", node.Id, env.groupA)

	body := requireAccess(t, env.alice, "a peer in the policy's source group should reach the internet through the exit node")
	assert.Equal(t, env.exitPeerTargetIP, body,
		"the target should see the exit peer's address, since the exit peer masquerades what it forwards")
	assertStaysWithoutAccess(t, env.bob, "a peer outside the policy's source groups should not reach the internet")
}

// TestExitNode_PolicySourceChange moves the policy from group A to group B.
func TestExitNode_PolicySourceChange(t *testing.T) {
	node := createExitNode(t, "en-source-change", true)
	policy := createPolicy(t, "en-source-change", node.Id, env.groupA)
	requireAccess(t, env.alice, "group A should have access before the change")

	updatePolicy(t, policy.Id, policyRequest("en-source-change", node.Id, true, env.groupB))

	requireAccess(t, env.bob, "group B should gain access once the policy names it")
	requireNoAccess(t, env.alice, "group A should lose access once the policy no longer names it")
}

// TestExitNode_PolicyMultipleSources gives two groups access, then removes one.
func TestExitNode_PolicyMultipleSources(t *testing.T) {
	node := createExitNode(t, "en-multi-source", true)
	policy := createPolicy(t, "en-multi-source", node.Id, env.groupA, env.groupB)

	requireAccess(t, env.alice, "group A should have access as one of the policy's sources")
	requireAccess(t, env.bob, "group B should have access as one of the policy's sources")

	updatePolicy(t, policy.Id, policyRequest("en-multi-source", node.Id, true, env.groupA))

	requireNoAccess(t, env.bob, "group B should lose access once it is removed from the sources")
	requireAccess(t, env.alice, "group A should keep access when another source is removed")
}

// TestExitNode_SourceGroupMembership changes who is in the source group, leaving the
// policy as it is.
func TestExitNode_SourceGroupMembership(t *testing.T) {
	node := createExitNode(t, "en-membership", true)
	createPolicy(t, "en-membership", node.Id, env.groupA)
	requireAccess(t, env.alice, "group A should have access")

	setGroupPeers(t, env.groupA, env.alicePeerID, env.bobPeerID)
	t.Cleanup(func() { setGroupPeers(t, env.groupA, env.alicePeerID) })
	requireAccess(t, env.bob, "a peer added to the source group should gain access")

	setGroupPeers(t, env.groupA, env.alicePeerID)
	requireNoAccess(t, env.bob, "a peer removed from the source group should lose access")
	requireAccess(t, env.alice, "the peers left in the source group should keep access")
}

// TestExitNode_PolicyDisabled turns the policy off and on again.
func TestExitNode_PolicyDisabled(t *testing.T) {
	node := createExitNode(t, "en-policy-disabled", true)
	policy := createPolicy(t, "en-policy-disabled", node.Id, env.groupA)
	requireAccess(t, env.alice, "group A should have access while the policy is enabled")

	updatePolicy(t, policy.Id, policyRequest("en-policy-disabled", node.Id, false, env.groupA))
	requireNoAccess(t, env.alice, "a disabled policy should grant no access")

	updatePolicy(t, policy.Id, policyRequest("en-policy-disabled", node.Id, true, env.groupA))
	requireAccess(t, env.alice, "re-enabling the policy should restore access")
}

// TestExitNode_PolicyDeleted deletes the only policy that targets the exit node.
func TestExitNode_PolicyDeleted(t *testing.T) {
	node := createExitNode(t, "en-policy-deleted", true)
	policy := createPolicy(t, "en-policy-deleted", node.Id, env.groupA)
	requireAccess(t, env.alice, "group A should have access while the policy exists")

	require.NoError(t, srv.API().Policies.Delete(context.Background(), *policy.Id), "delete policy")

	requireNoAccess(t, env.alice, "deleting the policy should remove access")
	_, err := srv.GetExitNode(context.Background(), node.Id)
	assert.NoError(t, err, "deleting a policy should leave its exit node in place")
}

// TestExitNode_Deleted deletes the exit node, which also deletes its policies.
func TestExitNode_Deleted(t *testing.T) {
	node := createExitNode(t, "en-deleted", true)
	policy := createPolicy(t, "en-deleted", node.Id, env.groupA)
	requireAccess(t, env.alice, "group A should have access while the exit node exists")

	require.NoError(t, srv.DeleteExitNode(context.Background(), node.Id), "delete exit node")

	requireNoAccess(t, env.alice, "deleting the exit node should remove access")
	_, err := srv.API().Policies.Get(context.Background(), *policy.Id)
	assert.Error(t, err, "deleting the exit node should delete the policies that target it")
}

// TestExitNode_Disabled turns off the exit node, then only its peer.
func TestExitNode_Disabled(t *testing.T) {
	node := createExitNode(t, "en-disabled", true)
	createPolicy(t, "en-disabled", node.Id, env.groupA)
	requireAccess(t, env.alice, "group A should have access while the exit node is enabled")

	updateExitNode(t, node.Id, exitNodeRequest("en-disabled", true, false, true))
	requireNoAccess(t, env.alice, "a disabled exit node should route nothing")

	updateExitNode(t, node.Id, exitNodeRequest("en-disabled", true, true, true))
	requireAccess(t, env.alice, "re-enabling the exit node should restore access")

	updateExitNode(t, node.Id, exitNodeRequest("en-disabled", true, true, false))
	requireNoAccess(t, env.alice, "an exit node whose only peer is disabled should route nothing")
}

// TestExitNode_AutoApplyOff checks that an exit node that is not auto applied reaches
// the client unselected, and routes once the user selects it.
func TestExitNode_AutoApplyOff(t *testing.T) {
	const name = "en-manual"
	node := createExitNode(t, name, false)
	createPolicy(t, name, node.Id, env.groupA)

	require.Eventually(t, func() bool {
		_, out, err := env.alice.Exec(context.Background(), "netbird", "networks", "list")
		return err == nil && strings.Contains(out, name)
	}, propagationTimeout, pollInterval, "the exit node should reach the client before its selection is checked")
	assertStaysWithoutAccess(t, env.alice, "an exit node that is not auto applied should stay unselected")

	code, out, err := env.alice.Exec(context.Background(), "netbird", "networks", "select", name)
	require.NoError(t, err, "select the exit node")
	require.Zerof(t, code, "netbird networks select should succeed: %s", out)

	requireAccess(t, env.alice, "a selected exit node should route the user's internet traffic")
}

// createExitNode creates an exit node routed by the exit peer. Its cleanup deletes it
// and waits for both user peers to lose access, so the next test starts clean.
func createExitNode(t *testing.T, name string, autoApply bool) api.ExitNode {
	t.Helper()
	node, err := srv.CreateExitNode(context.Background(), exitNodeRequest(name, autoApply, true, true))
	require.NoError(t, err, "create exit node %s", name)
	t.Cleanup(func() {
		_ = srv.DeleteExitNode(context.Background(), node.Id)
		requireNoAccess(t, env.alice, "no access should remain once the test's exit node is deleted")
		requireNoAccess(t, env.bob, "no access should remain once the test's exit node is deleted")
	})
	return node
}

func exitNodeRequest(name string, autoApply, enabled, peerEnabled bool) api.ExitNodeRequest {
	return api.ExitNodeRequest{
		Name:      name,
		Enabled:   enabled,
		AutoApply: autoApply,
		Peers:     []api.ExitNodePeer{{PeerId: env.exitPeerID, Metric: 100, Enabled: peerEnabled}},
	}
}

func updateExitNode(t *testing.T, id string, req api.ExitNodeRequest) {
	t.Helper()
	_, err := srv.UpdateExitNode(context.Background(), id, req)
	require.NoError(t, err, "update exit node %s", id)
}

// createPolicy creates a policy giving the source groups access to the exit node.
func createPolicy(t *testing.T, name, exitNodeID string, sources ...string) *api.Policy {
	t.Helper()
	policy, err := srv.API().Policies.Create(context.Background(), policyRequest(name, exitNodeID, true, sources...))
	require.NoError(t, err, "create policy %s", name)
	t.Cleanup(func() {
		if policy.Id != nil {
			_ = srv.API().Policies.Delete(context.Background(), *policy.Id)
		}
	})
	return policy
}

func policyRequest(name, exitNodeID string, enabled bool, sources ...string) api.PolicyUpdate {
	return api.PolicyUpdate{
		Name:    name,
		Enabled: enabled,
		Rules: []api.PolicyRuleUpdate{{
			Name:                name,
			Enabled:             enabled,
			Action:              api.PolicyRuleUpdateActionAccept,
			Protocol:            api.PolicyRuleUpdateProtocolAll,
			Sources:             &sources,
			DestinationResource: &api.Resource{Id: exitNodeID, Type: api.ResourceTypeExitNode},
		}},
	}
}

func updatePolicy(t *testing.T, id *string, req api.PolicyUpdate) {
	t.Helper()
	require.NotNil(t, id, "the policy should have an ID")
	_, err := srv.API().Policies.Update(context.Background(), *id, api.PolicyCreate(req))
	require.NoError(t, err, "update policy %s", *id)
}

// setGroupPeers replaces the group's peers.
func setGroupPeers(t *testing.T, groupID string, peerIDs ...string) {
	t.Helper()
	grp, err := srv.API().Groups.Get(context.Background(), groupID)
	require.NoError(t, err, "get group %s", groupID)
	_, err = srv.API().Groups.Update(context.Background(), groupID, api.PutApiGroupsGroupIdJSONRequestBody{
		Name:  grp.Name,
		Peers: &peerIDs,
	})
	require.NoError(t, err, "update group %s", groupID)
}

// fetch requests the target from inside the peer, returning the body and whether the
// request succeeded.
func fetch(cl *harness.Client) (string, bool) {
	code, out, err := cl.Exec(context.Background(), "wget", "-q", "-O", "-", "-T", "3", env.target.URL())
	return strings.TrimSpace(out), err == nil && code == 0
}

// requireAccess waits until the peer reaches the target and returns the response body.
func requireAccess(t *testing.T, cl *harness.Client, msg string) string {
	t.Helper()
	var body string
	require.Eventually(t, func() bool {
		var ok bool
		body, ok = fetch(cl)
		return ok
	}, propagationTimeout, pollInterval, "%s: %s", cl.Hostname(), msg)
	return body
}

// requireNoAccess waits until the peer can no longer reach the target.
func requireNoAccess(t *testing.T, cl *harness.Client, msg string) {
	t.Helper()
	require.Eventually(t, func() bool {
		_, ok := fetch(cl)
		return !ok
	}, propagationTimeout, pollInterval, "%s: %s", cl.Hostname(), msg)
}

// assertStaysWithoutAccess checks that the peer cannot reach the target for the whole
// deny window.
func assertStaysWithoutAccess(t *testing.T, cl *harness.Client, msg string) {
	t.Helper()
	assert.Never(t, func() bool {
		_, ok := fetch(cl)
		return ok
	}, denyWindow, pollInterval, "%s: %s", cl.Hostname(), msg)
}
