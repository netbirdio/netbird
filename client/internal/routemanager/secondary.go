package routemanager

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/coexist"
	"github.com/netbirdio/netbird/client/internal/instance"
	cProto "github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/route"
)

// errExitNodeInSecondary refuses a user's exit-node selection in a secondary
// installation.
var errExitNodeInSecondary = errors.New("exit nodes are disabled in a secondary installation")

// secondaryState tracks what a secondary installation keeps out of its routing:
// the exit nodes it ignored, and the identical routes it already reported.
type secondaryState struct {
	mu            sync.Mutex
	exitNodes     map[route.NetID]struct{}
	loggedIgnored bool
	reported      map[netip.Prefix]struct{}
}

// isRefusedExitRoute reports whether a route is a default route that a
// secondary installation must not install. Two default routes tie, and a
// secondary's exit node would capture the primary's traffic.
func isRefusedExitRoute(inst instance.Instance, r *route.Route) bool {
	if !inst.IsSecondary() || r.IsDynamic() {
		return false
	}
	return route.IsV4DefaultRoute(r.Network) || route.IsV6DefaultRoute(r.Network)
}

// setIgnoredExitNodes records the exit nodes of the latest network map that a
// secondary ignores, and logs once that it does.
func (s *secondaryState) setIgnoredExitNodes(ids map[route.NetID]struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.exitNodes = ids
	if len(ids) > 0 && !s.loggedIgnored {
		s.loggedIgnored = true
		log.Infof("ignoring %d exit node(s): exit nodes are disabled in a secondary installation", len(ids))
	}
}

// checkSelection refuses a selection that names an ignored exit node.
func (s *secondaryState) checkSelection(ids []route.NetID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, id := range ids {
		if _, ok := s.exitNodes[id]; ok {
			return errExitNodeInSecondary
		}
	}
	return nil
}

// newlyIdentical returns the prefixes of identical not reported before.
func (s *secondaryState) newlyIdentical(identical []netip.Prefix) []netip.Prefix {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.reported == nil {
		s.reported = make(map[netip.Prefix]struct{})
	}
	var out []netip.Prefix
	for _, p := range identical {
		if _, ok := s.reported[p]; !ok {
			s.reported[p] = struct{}{}
			out = append(out, p)
		}
	}
	return out
}

// warnIdenticalRoutes reports the routes of a secondary that another NetBird
// adapter routes too: the primary wins them, through its lower interface
// metric, so this installation does not reach them.
func (m *DefaultManager) warnIdenticalRoutes(networks route.HAMap) {
	if !instance.Current().IsSecondary() || m.wgInterface == nil {
		return
	}
	var own []netip.Prefix
	for _, routes := range networks {
		for _, r := range routes {
			if !r.IsDynamic() && r.Network.IsValid() {
				own = append(own, r.Network)
			}
		}
	}
	if len(own) == 0 {
		return
	}
	others, err := coexist.OtherOverlayRoutes(m.wgInterface.Name())
	if err != nil {
		log.Debugf("read the routes of other NetBird adapters: %v", err)
		return
	}
	identical := m.secondary.newlyIdentical(coexist.IdenticalRoutes(own, others))
	if len(identical) == 0 {
		return
	}
	msg := fmt.Sprintf("Another NetBird installation also routes %v; traffic for it goes through the primary installation.", identical)
	log.Warn(msg)
	if m.statusRecorder != nil {
		m.statusRecorder.PublishEvent(cProto.SystemEvent_WARNING, cProto.SystemEvent_NETWORK, msg, msg, nil)
	}
}
