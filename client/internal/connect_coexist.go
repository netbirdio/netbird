package internal

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/internal/coexist"
	"github.com/netbirdio/netbird/client/internal/instance"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/mdm"
	cProto "github.com/netbirdio/netbird/client/proto"
)

// errNamedInstallationsDisabled is returned when machine policy forbids named
// installations.
var errNamedInstallationsDisabled = errors.New("named installations are disabled by policy (disableNamedInstallations)")

// publishedCoexistence keeps a coexistence message from being published again
// on every reconnect attempt.
var publishedCoexistence sync.Map

// checkNamedAllowed refuses to connect a named installation when the machine
// policy forbids named installations.
func checkNamedAllowed(inst instance.Instance, policy *mdm.Policy) error {
	if inst.IsDefault() || !policy.NamedInstallationsDisabled() {
		return nil
	}
	return errNamedInstallationsDisabled
}

// checkCoexistence runs before a named installation brings its tunnel up. Two
// primaries are reported; a secondary whose overlay overlaps another NetBird
// adapter does not connect; routes of another installation inside the overlay
// are reported. The default installation is not checked, as before.
func checkCoexistence(recorder *peer.Status, inst instance.Instance, cfg *EngineConfig) error {
	if inst.IsDefault() {
		return nil
	}

	if other, ok := coexist.OtherPrimary(inst); ok {
		publishCoexistence(recorder, cProto.SystemEvent_WARNING, fmt.Sprintf(
			"Another primary installation exists: %s. Two primaries compete for exit nodes and system DNS.", other))
	}

	if err := coexist.CheckOverlay(inst, cfg.WgIfaceName, cfg.WgAddr); err != nil {
		publishCoexistence(recorder, cProto.SystemEvent_ERROR, err.Error())
		return err
	}

	if !inst.IsSecondary() {
		return nil
	}
	routes, err := coexist.OtherOverlayRoutes(cfg.WgIfaceName)
	if err != nil {
		log.Warnf("read the routes of other NetBird adapters: %v", err)
		return nil
	}
	if partial := coexist.PartialOverlaps(coexist.OverlayPrefixes(cfg.WgAddr), routes); len(partial) > 0 {
		publishCoexistence(recorder, cProto.SystemEvent_WARNING, fmt.Sprintf(
			"Another NetBird installation routes %s inside this installation's overlay; traffic to it goes to the other network.",
			joinPrefixes(partial)))
	}
	return nil
}

// watchCoexistence runs while a named secondary is connected. When another
// NetBird adapter later gets an address inside this installation's overlay, it
// reports the conflict and restarts the client; the connect check then keeps
// the installation disconnected until the conflict is gone.
func watchCoexistence(ctx context.Context, recorder *peer.Status, inst instance.Instance, ifaceName string,
	addr wgaddr.Address, restart func()) {
	c, ok := coexist.WatchOverlay(ctx, inst, ifaceName, addr)
	if !ok {
		return
	}
	publishCoexistence(recorder, cProto.SystemEvent_ERROR, c.Error())
	restart()
}

func publishCoexistence(recorder *peer.Status, severity cProto.SystemEvent_Severity, msg string) {
	if _, seen := publishedCoexistence.LoadOrStore(msg, struct{}{}); seen {
		return
	}
	log.Warn(msg)
	if recorder != nil {
		recorder.PublishEvent(severity, cProto.SystemEvent_SYSTEM, msg, msg, nil)
	}
}

func joinPrefixes[T fmt.Stringer](ps []T) string {
	s := make([]string, 0, len(ps))
	for _, p := range ps {
		s = append(s, p.String())
	}
	return strings.Join(s, ", ")
}
