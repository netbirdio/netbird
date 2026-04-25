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
// needs to deal with. Each phase is in its own helper to keep the function
// under SonarCloud's cognitive-complexity + length thresholds.
func (am *DefaultAccountManager) EnrollEntraDevicePeer(
	ctx context.Context,
	input ed.EnrollPeerInput,
) (*ed.EnrollPeerResult, error) {
	if err := validateEnrollInput(ctx, am, input); err != nil {
		return nil, err
	}

	hostname := deriveHostname(input)
	newPeer := buildEntraPeer(input, hostname)

	settings, err := am.Store.GetAccountSettings(ctx, store.LockingStrengthNone, input.AccountID)
	if err != nil {
		return nil, fmt.Errorf("failed to get account settings: %w", err)
	}

	am.geoEnrichPeer(ctx, newPeer)

	// Let the integrated peer validator (e.g. approval workflow) prep the
	// peer so approval policies still apply.
	newPeer = am.integratedPeerValidator.PreparePeer(ctx, input.AccountID, newPeer, input.AutoGroups, settings.Extra, false)

	if err := am.allocateEntraPeer(ctx, newPeer, input, hostname); err != nil {
		return nil, err
	}

	if input.Ephemeral {
		am.networkMapController.TrackEphemeralPeer(ctx, newPeer)
	}

	am.emitEntraPeerAddedEvent(ctx, newPeer, input, settings)

	if err := am.networkMapController.OnPeersAdded(ctx, input.AccountID, []string{newPeer.ID}); err != nil {
		log.WithContext(ctx).Errorf("failed to update network map cache for entra peer %s: %v", newPeer.ID, err)
	}

	_, netMap, checks, _, err := am.networkMapController.GetValidatedPeerWithMap(ctx, false, input.AccountID, newPeer)
	if err != nil {
		return nil, fmt.Errorf("failed to build network map for entra peer: %w", err)
	}

	return &ed.EnrollPeerResult{
		PeerID:        newPeer.ID,
		NetbirdConfig: netbirdConfigToMap(am, settings),
		PeerConfig:    peerConfigToMap(newPeer, netMap),
		Checks:        checksToMaps(checks),
	}, nil
}

// validateEnrollInput runs the cheap input-shape checks + duplicate-pubkey
// guard that AddPeer also performs.
func validateEnrollInput(ctx context.Context, am *DefaultAccountManager, input ed.EnrollPeerInput) error {
	if input.AccountID == "" {
		return status.Errorf(status.InvalidArgument, "account_id is required")
	}
	if input.WGPubKey == "" {
		return status.Errorf(status.InvalidArgument, "wg_pub_key is required")
	}
	if _, err := am.Store.GetPeerByPeerPubKey(ctx, store.LockingStrengthNone, input.WGPubKey); err == nil {
		return status.Errorf(status.PreconditionFailed, "peer has already been registered")
	}
	if err := domain.ValidateDomainsList(input.ExtraDNSLabels); err != nil {
		return status.Errorf(status.InvalidArgument, "invalid extra DNS labels: %v", err)
	}
	return nil
}

// buildEntraPeer builds the peer skeleton. Entra-enrolled peers are *not*
// SSO peers (LoginExpirationEnabled is false) because the device cert — not
// the user's JWT — is what authenticated them; their re-auth story is
// continuous-revalidation against Entra, not interactive SSO.
func buildEntraPeer(input ed.EnrollPeerInput, hostname string) *nbpeer.Peer {
	registrationTime := time.Now().UTC()
	p := &nbpeer.Peer{
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
	p.Meta.Hostname = hostname
	if ip := parseIP(input.ConnectionIP); ip != nil {
		p.Location.ConnectionIP = ip
	}
	return p
}

// geoEnrichPeer performs a best-effort geo lookup; failures are logged and
// do not prevent enrolment.
func (am *DefaultAccountManager) geoEnrichPeer(ctx context.Context, p *nbpeer.Peer) {
	if am.geo == nil || p.Location.ConnectionIP == nil {
		return
	}
	location, gerr := am.geo.Lookup(p.Location.ConnectionIP)
	if gerr != nil {
		log.WithContext(ctx).Warnf("failed to get geo for enrolled peer %s: %v", p.Location.ConnectionIP, gerr)
		return
	}
	p.Location.CountryCode = location.Country.ISOCode
	p.Location.CityName = location.City.Names.En
	p.Location.GeoNameID = location.City.GeonameID
}

// allocateEntraPeer runs the IP + DNS-label allocation loop inside a
// transaction and retries on unique-constraint collisions.
func (am *DefaultAccountManager) allocateEntraPeer(ctx context.Context, newPeer *nbpeer.Peer, input ed.EnrollPeerInput, hostname string) error {
	network, err := am.Store.GetAccountNetwork(ctx, store.LockingStrengthNone, input.AccountID)
	if err != nil {
		return fmt.Errorf("failed getting network: %w", err)
	}

	const maxAttempts = 10
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		freeIP, aerr := types.AllocateRandomPeerIP(network.Net)
		if aerr != nil {
			return fmt.Errorf("failed to get free IP: %w", aerr)
		}
		freeLabel, lerr := pickDNSLabel(freeIP, hostname, input.Ephemeral, attempt)
		if lerr != nil {
			return fmt.Errorf("failed to get DNS label: %w", lerr)
		}
		newPeer.IP = freeIP
		newPeer.DNSLabel = freeLabel

		txErr := am.Store.ExecuteInTransaction(ctx, func(tx store.Store) error {
			return persistEntraPeerTx(ctx, tx, newPeer, input)
		})
		if txErr == nil {
			return nil
		}
		lastErr = txErr
		if isUniqueConstraintError(txErr) {
			log.WithContext(ctx).WithFields(log.Fields{"dns_label": freeLabel, "ip": freeIP}).
				Tracef("entra enrolment attempt %d collided, retrying: %v", attempt, txErr)
			continue
		}
		return fmt.Errorf("failed to add entra-enrolled peer: %w", txErr)
	}
	return fmt.Errorf("failed to add entra-enrolled peer after %d attempts: %w", maxAttempts, lastErr)
}

// pickDNSLabel chooses a DNS label strategy — ephemeral / retry attempts get
// IP-suffixed labels, first non-ephemeral attempts reuse the hostname-derived
// label.
func pickDNSLabel(freeIP net.IP, hostname string, ephemeral bool, attempt int) (string, error) {
	if ephemeral || attempt > 1 {
		return getPeerIPDNSLabel(freeIP, hostname)
	}
	return nbdns.GetParsedDomainLabel(hostname)
}

// persistEntraPeerTx runs the per-transaction DB writes: peer row, auto-group
// attachments, All-group attachment, and network-serial bump.
func persistEntraPeerTx(ctx context.Context, tx store.Store, newPeer *nbpeer.Peer, input ed.EnrollPeerInput) error {
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
}

// emitEntraPeerAddedEvent records a PeerAddedWithEntraDevice activity event
// with full audit metadata (matched mappings, resolution mode, applied
// auto-groups).
func (am *DefaultAccountManager) emitEntraPeerAddedEvent(ctx context.Context, newPeer *nbpeer.Peer, input ed.EnrollPeerInput, settings *types.Settings) {
	meta := newPeer.EventMeta(am.networkMapController.GetDNSDomain(settings))
	meta["entra_device_id"] = input.EntraDeviceID
	meta["entra_device_mapping_id"] = input.EntraDeviceMapping
	meta["resolution_mode"] = input.ResolutionMode
	meta["matched_mapping_ids"] = append([]string{}, input.MatchedMappingIDs...)
	meta["auto_groups_applied"] = append([]string{}, input.AutoGroups...)
	am.StoreEvent(ctx, input.EntraDeviceID, newPeer.ID, input.AccountID,
		ed.PeerAddedWithEntraDevice, meta)
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

