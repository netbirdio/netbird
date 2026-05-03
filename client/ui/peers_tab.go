//go:build !(linux && 386)

package main

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

	"github.com/netbirdio/netbird/client/proto"
)

// peersTabBundle is what buildPeersTabContent returns: the tab content
// that lives inside AppTabs PLUS the Show-Full checkbox + the refresh
// callback that the OUTER window footer needs (so the user has a single
// footer for both showFull-toggle and Refresh-trigger). Phase 3.7i.
type peersTabBundle struct {
	Content  fyne.CanvasObject
	ShowFull *widget.Check
	Refresh  func()
}

// buildPeersTabContent constructs the "Peers" tab content (counter +
// list of expandable peer rows). Show-Full + Refresh live in the outer
// window footer (returned via peersTabBundle so network.go can place
// them). Phase 3.7i of #5989.
func (s *serviceClient) buildPeersTabContent(ctx context.Context) peersTabBundle {
	summary := widget.NewLabel("")
	breakdown := widget.NewLabel("")
	listVBox := container.NewVBox()
	showFull := widget.NewCheck("Show full peer details", nil)

	// Per-peer expand state survives Refresh (otherwise every render
	// would collapse all rows the user just opened). Keyed by pubkey.
	expandedMu := sync.Mutex{}
	expanded := make(map[string]bool)

	render := func() {
		conn, err := s.getSrvClient(failFastTimeout)
		if err != nil {
			fyne.Do(func() { summary.SetText("Error: " + err.Error()) })
			return
		}
		callCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		st, err := conn.Status(callCtx, &proto.StatusRequest{GetFullPeerStatus: true})
		if err != nil {
			fyne.Do(func() { summary.SetText("Error: " + err.Error()) })
			return
		}
		fs := st.GetFullStatus()

		fyne.Do(func() {
			summary.SetText(fmt.Sprintf("%d of %d peers online (server)",
				fs.GetServerOnlinePeers(), fs.GetConfiguredPeersTotal()))
			breakdown.SetText(fmt.Sprintf("%d P2P | %d relayed | %d idle | %d offline",
				fs.GetP2PConnectedPeers(), fs.GetRelayedConnectedPeers(),
				fs.GetIdleOnlinePeers(), fs.GetServerOfflinePeers()))

			listVBox.Objects = nil
			peers := fs.GetPeers()
			sort.SliceStable(peers, func(i, j int) bool {
				gi, gj := peerGroup(peers[i]), peerGroup(peers[j])
				if gi != gj {
					return gi < gj
				}
				return strings.ToLower(peers[i].GetFqdn()) < strings.ToLower(peers[j].GetFqdn())
			})
			for _, p := range peers {
				listVBox.Add(newPeerRow(p, showFull.Checked, &expandedMu, expanded))
			}
			listVBox.Refresh()
		})
	}

	showFull.OnChanged = func(_ bool) { render() }

	// Lifecycle-safe periodic refresh: ctx-respecting, exits when the
	// serviceClient context is cancelled (i.e. the UI process shuts down).
	// 30 s polling -- daemon-RPC is local so cost is small.
	go func() {
		render()
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				render()
			}
		}
	}()

	// Place listVBox directly in Border center (no inner VScroll). The
	// outer Networks-window already wraps everything in a VScroll, so
	// nesting another would create double-scroll UX. Border center
	// auto-grows to fit listVBox content; outer scroll handles overflow.
	content := container.NewBorder(
		container.NewVBox(summary, breakdown),
		nil, nil, nil,
		listVBox,
	)
	return peersTabBundle{Content: content, ShowFull: showFull, Refresh: render}
}

// newPeerRow returns a single expandable row: a clickable header that
// dynamically adds/removes a detail label below it on tap. Expansion
// state is persisted in `expanded` (keyed by pubkey) so Refresh doesn't
// collapse rows the user just opened. Multiple rows can be expanded
// simultaneously (each row owns its own state). Phase 3.7i of #5989.
func newPeerRow(p *proto.PeerState, showFull bool, mu *sync.Mutex, expanded map[string]bool) *fyne.Container {
	pubkey := p.GetPubKey()
	titleCollapsed := fmt.Sprintf("▶  %s   %s   %s", peerGlyph(p), peerHostnameShort(p), peerModeTag(p))
	titleExpanded := fmt.Sprintf("▼  %s   %s   %s", peerGlyph(p), peerHostnameShort(p), peerModeTag(p))

	mu.Lock()
	startExpanded := expanded[pubkey]
	mu.Unlock()

	header := widget.NewButton(titleCollapsed, nil)
	header.Alignment = widget.ButtonAlignLeading
	header.Importance = widget.LowImportance

	box := container.NewVBox(header)
	var detail *widget.Label

	addDetail := func() {
		detail = widget.NewLabel(buildPeerDetailText(p, showFull))
		detail.Wrapping = fyne.TextWrapWord
		detail.TextStyle = fyne.TextStyle{Monospace: true}
		box.Add(detail)
		header.SetText(titleExpanded)
	}
	removeDetail := func() {
		if detail != nil {
			box.Remove(detail)
			detail = nil
		}
		header.SetText(titleCollapsed)
	}

	if startExpanded {
		addDetail()
	}

	header.OnTapped = func() {
		mu.Lock()
		nowExpanded := !expanded[pubkey]
		expanded[pubkey] = nowExpanded
		mu.Unlock()
		if nowExpanded {
			addDetail()
		} else {
			removeDetail()
		}
		box.Refresh()
	}
	return box
}

func peerGroup(p *proto.PeerState) int {
	if !p.GetServerOnline() {
		return 3
	}
	cs := strings.ToLower(p.GetConnStatus())
	if cs == "connected" && !p.GetRelayed() {
		return 0
	}
	if cs == "connected" && p.GetRelayed() {
		return 1
	}
	return 2
}

func peerGlyph(p *proto.PeerState) string {
	switch peerGroup(p) {
	case 0:
		return "[P2P]"
	case 1:
		return "[Relay]"
	case 2:
		return "[Idle]"
	default:
		return "[Offline]"
	}
}

func peerHostnameShort(p *proto.PeerState) string {
	fqdn := p.GetFqdn()
	if i := strings.Index(fqdn, "."); i > 0 {
		return fqdn[:i]
	}
	return fqdn
}

func peerModeTag(p *proto.PeerState) string {
	eff, cfg := p.GetEffectiveConnectionMode(), p.GetConfiguredConnectionMode()
	if eff == "" {
		return ""
	}
	if cfg != "" && cfg != eff {
		return "! " + eff + " (cfg: " + cfg + ")"
	}
	return eff
}

// buildPeerDetailText builds the per-peer detail text. Standard fields
// always shown. When `full` is true an additional section with the
// extra technical fields (transfer counters, configured timeouts, etc.)
// is appended.
func buildPeerDetailText(p *proto.PeerState, full bool) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "IP:                %s\n", p.GetIP())
	fmt.Fprintf(&sb, "FQDN:              %s\n", p.GetFqdn())
	connType := p.GetConnStatus()
	if p.GetRelayed() {
		connType += " (relayed)"
	}
	fmt.Fprintf(&sb, "Connection type:   %s\n", connType)
	fmt.Fprintf(&sb, "Effective mode:    %s\n", orDashStr(p.GetEffectiveConnectionMode()))
	if p.GetEffectiveConnectionMode() != p.GetConfiguredConnectionMode() && p.GetConfiguredConnectionMode() != "" {
		fmt.Fprintf(&sb, "Configured mode:   %s\n", orDashStr(p.GetConfiguredConnectionMode()))
	}
	if hs := p.GetLastWireguardHandshake(); hs != nil && hs.IsValid() {
		fmt.Fprintf(&sb, "Last handshake:    %s\n", hs.AsTime().Format(time.RFC3339))
	}
	fmt.Fprintf(&sb, "Latency:           %s\n", peerLatencyStr(p))
	if strings.EqualFold(p.GetConnStatus(), "connected") {
		if p.GetRelayed() {
			fmt.Fprintf(&sb, "Relay server:      %s\n", orDashStr(p.GetRelayAddress()))
		} else {
			fmt.Fprintf(&sb, "Local endpoint:    %s\n", orDashStr(p.GetLocalIceCandidateEndpoint()))
			fmt.Fprintf(&sb, "Remote endpoint:   %s\n", orDashStr(p.GetRemoteIceCandidateEndpoint()))
		}
	}
	if ls := p.GetLastSeenAtServer(); ls != nil && ls.IsValid() {
		fmt.Fprintf(&sb, "Last seen at srv:  %s\n", ls.AsTime().Format(time.RFC3339))
	}
	if g := p.GetGroups(); len(g) > 0 {
		fmt.Fprintf(&sb, "Groups:            %s\n", strings.Join(g, ", "))
	}

	if full {
		sb.WriteString("\n--- Full details ---\n")
		fmt.Fprintf(&sb, "Public key:        %s\n", p.GetPubKey())
		fmt.Fprintf(&sb, "Transfer rx/tx:    %s / %s\n",
			humanBytes(uint64(p.GetBytesRx())), humanBytes(uint64(p.GetBytesTx())))
		if eff := p.GetEffectiveRelayTimeoutSecs(); eff > 0 {
			fmt.Fprintf(&sb, "Relay timeout:     %d s (eff)\n", eff)
		}
		if eff := p.GetEffectiveP2PTimeoutSecs(); eff > 0 {
			fmt.Fprintf(&sb, "P2P timeout:       %d s (eff)\n", eff)
		}
		if eff := p.GetEffectiveP2PRetryMaxSecs(); eff > 0 {
			fmt.Fprintf(&sb, "P2P retry-max:     %d s (eff)\n", eff)
		}
		if local, remote := p.GetLocalIceCandidateType(), p.GetRemoteIceCandidateType(); local != "" || remote != "" {
			fmt.Fprintf(&sb, "ICE candidate L/R: %s / %s\n", orDashStr(local), orDashStr(remote))
		}
		if iceFails := p.GetIceBackoffFailures(); iceFails > 0 {
			fmt.Fprintf(&sb, "ICE backoff fails: %d\n", iceFails)
		}
	}
	return sb.String()
}

func orDashStr(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func peerLatencyStr(p *proto.PeerState) string {
	d := p.GetLatency().AsDuration()
	if d == 0 {
		return "-"
	}
	return d.Round(time.Microsecond).String()
}

func humanBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
