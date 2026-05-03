//go:build !(linux && 386)

package main

import (
	"context"
	"fmt"
	"sort"
	"strings"
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
				listVBox.Add(newPeerRow(p, showFull.Checked))
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

	// VScroll wraps the VBox so long lists scroll naturally. VBox packs
	// children tightly (each peer row sizes to its content). Multiple
	// rows can be expanded simultaneously since each row is independent.
	scroll := container.NewVScroll(listVBox)
	content := container.NewBorder(
		container.NewVBox(summary, breakdown),
		nil, nil, nil,
		scroll,
	)
	return peersTabBundle{Content: content, ShowFull: showFull, Refresh: render}
}

// newPeerRow returns a single expandable row: a clickable header + a
// hidden detail block that toggles visibility on tap. Sizes itself to
// content (no wasted vertical space). Phase 3.7i.
func newPeerRow(p *proto.PeerState, showFull bool) *fyne.Container {
	titleCollapsed := fmt.Sprintf("▶  %s   %s   %s", peerGlyph(p), peerHostnameShort(p), peerModeTag(p))
	titleExpanded := fmt.Sprintf("▼  %s   %s   %s", peerGlyph(p), peerHostnameShort(p), peerModeTag(p))

	header := widget.NewButton(titleCollapsed, nil)
	header.Alignment = widget.ButtonAlignLeading
	header.Importance = widget.LowImportance

	detail := widget.NewLabel(buildPeerDetailText(p, showFull))
	detail.Wrapping = fyne.TextWrapWord
	detail.TextStyle = fyne.TextStyle{Monospace: true}
	detail.Hide()

	row := container.NewVBox(header, detail)
	header.OnTapped = func() {
		if detail.Visible() {
			detail.Hide()
			header.SetText(titleCollapsed)
		} else {
			detail.Show()
			header.SetText(titleExpanded)
		}
	}
	return row
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
	// Phase 3.7i ships Standard B; Full toggle is wired but renders the
	// same content. No "-- Full details --" header in production.
	_ = full
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
