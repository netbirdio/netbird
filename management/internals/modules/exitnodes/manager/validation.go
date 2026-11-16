package manager

import (
	"context"
	"fmt"
	"slices"

	"github.com/netbirdio/netbird/management/internals/modules/exitnodes"
	"github.com/netbirdio/netbird/management/internals/shared/db"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/shared/management/status"
)

// references holds what validating an exit node needs from outside the
// exit_nodes table. It is read before the transaction: a store read inside it
// would wait for the connection the transaction holds on SQLite.
type references struct {
	groups          map[string]*types.Group
	requestedGroups map[string]struct{}
	peers           map[string]*nbpeer.Peer
	legacyRoutes    []*route.Route
}

// loadReferences reads the groups, peers and legacy 0.0.0.0/0 routes needed to
// validate node, and checks that everything node references exists.
func (m *managerImpl) loadReferences(ctx context.Context, accountID string, node *exitnodes.ExitNode) (*references, error) {
	existing, err := m.repo.ListByAccount(ctx, db.LockingStrengthNone, accountID)
	if err != nil {
		return nil, err
	}

	accountRoutes, err := m.store.GetAccountRoutes(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return nil, err
	}
	refs := &references{}
	for _, r := range accountRoutes {
		if isLegacyExitRoute(r) {
			refs.legacyRoutes = append(refs.legacyRoutes, r)
		}
	}

	groupIDs := collectGroupIDs(node, existing, refs.legacyRoutes)
	refs.requestedGroups = make(map[string]struct{}, len(groupIDs))
	for _, id := range groupIDs {
		refs.requestedGroups[id] = struct{}{}
	}
	if refs.groups, err = m.store.GetGroupsByIDs(ctx, store.LockingStrengthNone, accountID, groupIDs); err != nil {
		return nil, err
	}

	refs.peers = map[string]*nbpeer.Peer{}
	if peerIDs := collectPeerIDs(node); len(peerIDs) > 0 {
		if refs.peers, err = m.store.GetPeersByIDs(ctx, store.LockingStrengthNone, accountID, peerIDs); err != nil {
			return nil, err
		}
	}

	if err := refs.checkExist(node); err != nil {
		return nil, err
	}
	return refs, nil
}

// isLegacyExitRoute reports whether r is a 0.0.0.0/0 network route. Domain
// routes are skipped: older ones were stored with 0.0.0.0/0 as their network.
func isLegacyExitRoute(r *route.Route) bool {
	return !r.IsDynamic() && len(r.Domains) == 0 && route.IsV4DefaultRoute(r.Network)
}

func collectGroupIDs(node *exitnodes.ExitNode, existing []*exitnodes.ExitNode, legacyRoutes []*route.Route) []string {
	ids := slices.Concat(node.Groups, node.AccessControlGroups)
	for _, n := range append([]*exitnodes.ExitNode{node}, existing...) {
		for _, rp := range n.RoutingPeers {
			ids = append(ids, rp.PeerGroups...)
		}
	}
	for _, r := range legacyRoutes {
		ids = append(ids, r.PeerGroups...)
	}
	slices.Sort(ids)
	return slices.Compact(ids)
}

func collectPeerIDs(node *exitnodes.ExitNode) []string {
	var ids []string
	for _, rp := range node.RoutingPeers {
		if rp.Peer != "" {
			ids = append(ids, rp.Peer)
		}
	}
	slices.Sort(ids)
	return slices.Compact(ids)
}

func (r *references) checkExist(node *exitnodes.ExitNode) error {
	for _, id := range slices.Concat(node.Groups, node.AccessControlGroups) {
		if _, ok := r.groups[id]; !ok {
			return status.Errorf(status.InvalidArgument, "group %s not found", id)
		}
	}
	for _, rp := range node.RoutingPeers {
		if rp.Peer != "" {
			if _, ok := r.peers[rp.Peer]; !ok {
				return status.Errorf(status.InvalidArgument, "peer %s not found", rp.Peer)
			}
		}
		for _, id := range rp.PeerGroups {
			if _, ok := r.groups[id]; !ok {
				return status.Errorf(status.InvalidArgument, "peer group %s not found", id)
			}
		}
	}
	return nil
}

// checkConflicts enforces the account-wide rules against the exit nodes read
// under lock: the name is unique among exit nodes and legacy exit routes, and
// no peer serves 0.0.0.0/0 more than once.
func (r *references) checkConflicts(node *exitnodes.ExitNode, nodes []*exitnodes.ExitNode) error {
	if err := r.checkName(node, nodes); err != nil {
		return err
	}

	claims := newPeerClaims(r)
	for _, legacy := range r.legacyRoutes {
		if err := claims.claim(fmt.Sprintf("route %q", legacy.NetID), legacy.Peer, legacy.PeerGroups); err != nil {
			return err
		}
	}
	for _, other := range nodes {
		if other.ID == node.ID {
			continue
		}
		for _, rp := range other.RoutingPeers {
			if err := claims.claim(fmt.Sprintf("exit node %q", other.Name), rp.Peer, rp.PeerGroups); err != nil {
				return err
			}
		}
	}

	for _, rp := range node.RoutingPeers {
		if err := claims.check(rp.Peer, rp.PeerGroups); err != nil {
			return err
		}
		if err := claims.claim("another routing peer entry of this exit node", rp.Peer, rp.PeerGroups); err != nil {
			return err
		}
	}
	return nil
}

func (r *references) checkName(node *exitnodes.ExitNode, nodes []*exitnodes.ExitNode) error {
	for _, legacy := range r.legacyRoutes {
		if string(legacy.NetID) == node.Name {
			return status.Errorf(status.AlreadyExists, "name %q is already used by a 0.0.0.0/0 route", node.Name)
		}
	}
	for _, other := range nodes {
		if other.ID != node.ID && other.Name == node.Name {
			return status.Errorf(status.AlreadyExists, "exit node with name %q already exists", node.Name)
		}
	}
	return nil
}

// peerClaims records which peers and peer groups already serve 0.0.0.0/0 and
// through what, mirroring the per-prefix check of legacy routes.
type peerClaims struct {
	refs   *references
	peers  map[string]string
	groups map[string]string
}

func newPeerClaims(refs *references) *peerClaims {
	return &peerClaims{refs: refs, peers: map[string]string{}, groups: map[string]string{}}
}

func (c *peerClaims) claim(owner, peer string, peerGroups []string) error {
	if peer != "" {
		c.peers[peer] = owner
	}
	for _, groupID := range peerGroups {
		members, err := c.members(groupID)
		if err != nil {
			return err
		}
		c.groups[groupID] = owner
		for _, peerID := range members {
			c.peers[peerID] = owner
		}
	}
	return nil
}

func (c *peerClaims) check(peer string, peerGroups []string) error {
	if owner, ok := c.peers[peer]; peer != "" && ok {
		return status.Errorf(status.AlreadyExists, "peer %s already serves 0.0.0.0/0 through %s", peer, owner)
	}
	for _, groupID := range peerGroups {
		if owner, ok := c.groups[groupID]; ok {
			return status.Errorf(status.AlreadyExists, "peer group %s already serves 0.0.0.0/0 through %s", c.groupName(groupID), owner)
		}
		members, err := c.members(groupID)
		if err != nil {
			return err
		}
		for _, peerID := range members {
			if owner, ok := c.peers[peerID]; ok {
				return status.Errorf(status.AlreadyExists, "peer %s from group %s already serves 0.0.0.0/0 through %s", peerID, c.groupName(groupID), owner)
			}
		}
	}
	return nil
}

// members resolves a peer group from the references. A group that was read
// but not found has no members; a group that was never read was added by a
// concurrent write after the references were loaded.
func (c *peerClaims) members(groupID string) ([]string, error) {
	if group, ok := c.refs.groups[groupID]; ok {
		return group.Peers, nil
	}
	if _, ok := c.refs.requestedGroups[groupID]; ok {
		return nil, nil
	}
	return nil, status.Errorf(status.PreconditionFailed, "exit nodes changed while the request was validated, retry it")
}

func (c *peerClaims) groupName(groupID string) string {
	if group, ok := c.refs.groups[groupID]; ok && group.Name != "" {
		return group.Name
	}
	return groupID
}
