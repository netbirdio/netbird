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

// buildPeersTabContent constructs the "Peers" tab in the Networks
// window: counter widget on top, sorted accordion list below,
// Show-Full checkbox + Refresh button at the bottom. Phase 3.7i of #5989.
func (s *serviceClient) buildPeersTabContent(ctx context.Context) fyne.CanvasObject {
	summary := widget.NewLabel("")
	breakdown := widget.NewLabel("")
	peerList := widget.NewAccordion()
	showFull := widget.NewCheck("Show full peer details", nil)
	refreshBtn := widget.NewButton("Refresh", nil)

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
			summary.SetText(fmt.Sprintf("%d of %d peers online",
				fs.GetServerOnlinePeers(), fs.GetConfiguredPeersTotal()))
			breakdown.SetText(fmt.Sprintf("P2P: %d   Relayed: %d   Idle: %d   Offline: %d",
				fs.GetP2PConnectedPeers(), fs.GetRelayedConnectedPeers(),
				fs.GetIdleOnlinePeers(), fs.GetServerOfflinePeers()))

			peerList.Items = nil
			peers := fs.GetPeers()
			sort.SliceStable(peers, func(i, j int) bool {
				gi, gj := peerGroup(peers[i]), peerGroup(peers[j])
				if gi != gj {
					return gi < gj
				}
				return strings.ToLower(peers[i].GetFqdn()) < strings.ToLower(peers[j].GetFqdn())
			})
			for _, p := range peers {
				title := fmt.Sprintf("%s   %s   %s", peerGlyph(p), peerHostnameShort(p), peerModeTag(p))
				detail := widget.NewLabel(buildPeerDetailText(p, showFull.Checked))
				detail.Wrapping = fyne.TextWrapWord
				peerList.Append(widget.NewAccordionItem(title, detail))
			}
			peerList.Refresh()
		})
	}

	refreshBtn.OnTapped = render
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

	// Wrap the scroll in a Stack (max layout) so it expands to fill the
	// center area regardless of the Accordion's natural content height.
	// Otherwise the VScroll collapses to the Accordion's intrinsic size
	// (often tiny when only one item is expanded) instead of taking the
	// full available space.
	scroll := container.NewVScroll(peerList)
	return container.NewBorder(
		container.NewVBox(summary, breakdown),
		container.NewHBox(showFull, refreshBtn),
		nil, nil,
		container.NewStack(scroll),
	)
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
