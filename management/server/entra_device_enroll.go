package server

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/rs/xid"
	log "github.com/sirupsen/logrus"

	nbdns "github.com/netbirdio/netbird/dns"
	ed "github.com/netbirdio/netbird/management/server/integrations/entra_device"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/domain"
	"github.com/netbirdio/netbird/shared/management/status"
)

// EnrollEntraDevicePeer creates a new peer from an Entra-validated enrolment
// input. The Entra integration has already verified the device certificate,
// looked up the device in Graph, and resolved the mapping; this method is
// focused on the NetBird-side peer creation and group assignment.
//
// It mirrors the essential data-writing portion of AddPeer (IP allocation with
// retries, group assignment, All-group membership, ephemeral tracking, network
// serial bump) without the setup-key / user-JWT auth branches that AddPeer
// needs to deal with.
func (am *DefaultAccountManager) EnrollEntraDevicePeer(
	ctx context.Context,
	input ed.EnrollPeerInput,
) (*ed.EnrollPeerResult, error) {

	if input.AccountID == "" {
		return nil, status.Errorf(status.InvalidArgument, "account_id is required")
	}
	if input.WGPubKey == "" {
		return nil, status.Errorf(status.InvalidArgument, "wg_pub_key is required")
	}

	// Reject duplicate registration early, mirroring AddPeer's guard.
	if _, err := am.Store.GetPeerByPeerPubKey(ctx, store.LockingStrengthNone, input.WGPubKey); err == nil {
		return nil, status.Errorf(status.PreconditionFailed, "peer has already been registered")
	}

	// Validate extra DNS labels are well-formed (AddPeer does the same thing).
	if err := domain.ValidateDomainsList(input.ExtraDNSLabels); err != nil {
		return nil, status.Errorf(status.InvalidArgument, "invalid extra DNS labels: %v", err)
	}

	// Build the peer skeleton. Entra-enrolled peers are *not* SSO peers
	// (LoginExpirationEnabled is false) because the device cert — not the
	// user's JWT — is what authenticated them; their re-auth story is
	// continuous-revalidation against Entra, not interactive SSO.
	registrationTime := time.Now().UTC()
	hostname := deriveHostname(input)
	newPeer := &nbpeer.Peer{
		ID:                          xid.New().String(),
		AccountID:                   input.AccountID,
		Key:                         input.WGPubKey,
		Name:                        hostname,
		SSHKey:                      input.SSHPubKey,
		SSHEnabled:                  false,
		Status:                      &nbpeer.PeerStatus{Connected: false, LastSeen: registrationTime},
		LastLogin:                   &registrationTime,
		CreatedAt:                   registrationTime,
		LoginExpirationEnabled:      false,
		InactivityExpirationEnabled: false,
		Ephemeral:                   input.Ephemeral,
		ExtraDNSLabels:              input.ExtraDNSLabels,
		AllowExtraDNSLabels:         input.AllowExtraDNSLabels,
	}
	newPeer.Meta.Hostname = hostname

	if ip := parseIP(input.ConnectionIP); ip != nil {
		newPeer.Location.ConnectionIP = ip
	}

	settings, err := am.Store.GetAccountSettings(ctx, store.LockingStrengthNone, input.AccountID)
	if err != nil {
		return nil, fmt.Errorf("failed to get account settings: %w", err)
	}

	// Geo lookup (best-effort).
	if am.geo != nil && newPeer.Location.ConnectionIP != nil {
		location, gerr := am.geo.Lookup(newPeer.Location.ConnectionIP)
		if gerr != nil {
			log.WithContext(ctx).Warnf("failed to get geo for enrolled peer %s: %v", newPeer.Location.ConnectionIP, gerr)
		} else {
			newPeer.Location.CountryCode = location.Country.ISOCode
			newPeer.Location.CityName = location.City.Names.En
			newPeer.Location.GeoNameID = location.City.GeonameID
		}
	}

	// Let the integrated peer validator (e.g. approval workflow) prep the
	// peer so approval policies still apply.
	newPeer = am.integratedPeerValidator.PreparePeer(ctx, input.AccountID, newPeer, input.AutoGroups, settings.Extra, false)

	network, err := am.Store.GetAccountNetwork(ctx, store.LockingStrengthNone, input.AccountID)
	if err != nil {
		return nil, fmt.Errorf("failed getting network: %w", err)
	}

	// Allocate IP + DNS label with retries on unique-constraint collisions.
	const maxAttempts = 10
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		freeIP, aerr := types.AllocateRandomPeerIP(network.Net)
		if aerr != nil {
			return nil, fmt.Errorf("failed to get free IP: %w", aerr)
		}

		var freeLabel string
		if input.Ephemeral || attempt > 1 {
			freeLabel, err = getPeerIPDNSLabel(freeIP, hostname)
		} else {
			freeLabel, err = nbdns.GetParsedDomainLabel(hostname)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to get DNS label: %w", err)
		}
		newPeer.IP = freeIP
		newPeer.DNSLabel = freeLabel

		err = am.Store.ExecuteInTransaction(ctx, func(tx store.Store) error {
			if err := tx.AddPeerToAccount(ctx, newPeer); err != nil {
				return err
			}
			for _, g := range input.AutoGroups {
				if err := tx.AddPeerToGroup(ctx, newPeer.AccountID, newPeer.ID, g); err != nil {
					return err
				}
			}
			if err := tx.AddPeerToAllGroup(ctx, input.AccountID, newPeer.ID); err != nil {
				return fmt.Errorf("failed adding peer to All group: %w", err)
			}
			return tx.IncrementNetworkSerial(ctx, input.AccountID)
		})
		if err == nil {
			break
		}
		if isUniqueConstraintError(err) {
			log.WithContext(ctx).WithFields(log.Fields{"dns_label": freeLabel, "ip": freeIP}).
				Tracef("entra enrolment attempt %d collided, retrying: %v", attempt, err)
			continue
		}
		return nil, fmt.Errorf("failed to add entra-enrolled peer: %w", err)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to add entra-enrolled peer after %d attempts: %w", maxAttempts, err)
	}

	if input.Ephemeral {
		am.networkMapController.TrackEphemeralPeer(ctx, newPeer)
	}

	// Emit an activity event so admins can audit enrolments. Meta includes
	// every contributing mapping so the resolution decision is auditable.
	meta := newPeer.EventMeta(am.networkMapController.GetDNSDomain(settings))
	meta["entra_device_id"] = input.EntraDeviceID
	meta["entra_device_mapping_id"] = input.EntraDeviceMapping
	meta["resolution_mode"] = input.ResolutionMode
	meta["matched_mapping_ids"] = append([]string{}, input.MatchedMappingIDs...)
	meta["auto_groups_applied"] = append([]string{}, input.AutoGroups...)
	am.StoreEvent(ctx, input.EntraDeviceID, newPeer.ID, input.AccountID,
		ed.PeerAddedWithEntraDevice, meta)

	// Update network map cache + produce an initial LoginResponse-shaped
	// payload to hand back to the client.
	if err := am.networkMapController.OnPeersAdded(ctx, input.AccountID, []string{newPeer.ID}); err != nil {
		log.WithContext(ctx).Errorf("failed to update network map cache for entra peer %s: %v", newPeer.ID, err)
	}

	validatedPeer, netMap, checks, _, err := am.networkMapController.GetValidatedPeerWithMap(ctx, false, input.AccountID, newPeer)
	if err != nil {
		return nil, fmt.Errorf("failed to build network map for entra peer: %w", err)
	}
	_ = validatedPeer // peer object returned to caller is not needed by Manager

	return &ed.EnrollPeerResult{
		PeerID:        newPeer.ID,
		NetbirdConfig: netbirdConfigToMap(am, settings),
		PeerConfig:    peerConfigToMap(newPeer, netMap),
		Checks:        checksToMaps(checks),
	}, nil
}

// AsEntraDevicePeerEnroller returns an ed.PeerEnroller adapter so the
// entra_device.Manager can call back into the account manager without
// depending on the server package.
func (am *DefaultAccountManager) AsEntraDevicePeerEnroller() ed.PeerEnroller {
	return &entraDevicePeerEnroller{am: am}
}

type entraDevicePeerEnroller struct {
	am *DefaultAccountManager
}

func (e *entraDevicePeerEnroller) EnrollEntraDevicePeer(ctx context.Context, in ed.EnrollPeerInput) (*ed.EnrollPeerResult, error) {
	return e.am.EnrollEntraDevicePeer(ctx, in)
}

// DeletePeer is a compensation hook invoked by the entra_device.Manager when
// a post-peer-creation step (currently bootstrap-token issuance) fails and
// would otherwise leave an orphan peer blocking re-enrolment. It is a no-op
// if the peer has already been deleted.
func (e *entraDevicePeerEnroller) DeletePeer(ctx context.Context, accountID, peerID string) error {
	if accountID == "" || peerID == "" {
		return nil
	}
	settings, err := e.am.Store.GetAccountSettings(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return fmt.Errorf("get account settings for entra compensation: %w", err)
	}
	return e.am.Store.ExecuteInTransaction(ctx, func(tx store.Store) error {
		peer, err := tx.GetPeerByID(ctx, store.LockingStrengthNone, accountID, peerID)
		if err != nil {
			// Peer already gone is not an error; we're compensating.
			return nil //nolint:nilerr // quiet on "already gone"
		}
		if _, err := deletePeers(ctx, e.am, tx, accountID, "entra-enroll-compensation", []*nbpeer.Peer{peer}, settings); err != nil {
			return fmt.Errorf("delete orphan entra peer %s: %w", peerID, err)
		}
		return tx.IncrementNetworkSerial(ctx, accountID)
	})
}

// --- helpers ---

func parseIP(s string) net.IP {
	if s == "" {
		return nil
	}
	if ip := net.ParseIP(s); ip != nil {
		return ip
	}
	// Try host:port / [host]:port forms (the latter is what Go emits for IPv6
	// remote addresses in r.RemoteAddr).
	if host, _, err := net.SplitHostPort(s); err == nil {
		return net.ParseIP(host)
	}
	return nil
}

func deriveHostname(input ed.EnrollPeerInput) string {
	if input.Hostname != "" {
		return input.Hostname
	}
	if input.EntraDeviceID != "" {
		return "entra-" + input.EntraDeviceID
	}
	return "entra-device"
}

// netbirdConfigToMap produces a minimal serialisable NetBird config for the
// enrolment response. Clients only need enough to bootstrap their gRPC
// connection; they will receive the full config on first Sync.
func netbirdConfigToMap(am *DefaultAccountManager, s *types.Settings) map[string]any {
	if am == nil || s == nil {
		return nil
	}
	return map[string]any{
		// The client will resync these on first Sync; we include nothing
		// sensitive here. A future improvement can mirror toNetbirdConfig()
		// from the gRPC server to hand the client a complete bootstrap.
		"dns_domain": am.networkMapController.GetDNSDomain(s),
	}
}

// peerConfigToMap returns a tiny, stable subset of the peer's network config
// that's useful to the enrolling client.
func peerConfigToMap(p *nbpeer.Peer, nm *types.NetworkMap) map[string]any {
	if p == nil {
		return nil
	}
	out := map[string]any{
		"address":  p.IP.String(),
		"dns_label": p.DNSLabel,
	}
	if nm != nil {
		out["network_serial"] = nm.Network.CurrentSerial()
	}
	return out
}

// checksToMaps exists so the entra package can stay decoupled from the posture
// types. It's only meant to be a lightweight summary for the HTTP response.
func checksToMaps(checks any) []map[string]any {
	// We don't surface any posture checks on enrolment; the client gets them
	// on first Sync. Kept as a stub so callers see a []map[string]any.
	_ = checks
	return nil
}

