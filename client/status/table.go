package status

import (
	"fmt"
	"strings"
	"text/tabwriter"
	"time"
)

// PeersTable renders the peers as an aligned table, one row per peer.
func (o *OutputOverview) PeersTable() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "Peers (%d/%d connected):\n", o.Peers.Connected, o.Peers.Total)

	tw := tabwriter.NewWriter(&sb, 0, 0, 3, ' ', 0)
	fmt.Fprintln(tw, "NAME\tIP\tSTATUS\tCONN\tLATENCY\tRX / TX")
	for _, p := range o.Peers.Details {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s / %s\n",
			shortName(p.FQDN),
			dashIfEmpty(p.IP),
			p.Status,
			dashIfEmpty(p.ConnType),
			tableLatency(p),
			toIEC(p.TransferReceived),
			toIEC(p.TransferSent),
		)
	}
	// The writer targets a strings.Builder, which never returns an error.
	_ = tw.Flush()

	return sb.String()
}

// shortName drops the domain suffix, which is the same for every peer.
func shortName(fqdn string) string {
	name, _, _ := strings.Cut(fqdn, ".")
	return dashIfEmpty(name)
}

func tableLatency(p PeerStateDetailOutput) string {
	if p.Latency <= 0 {
		return "-"
	}
	if p.Latency >= time.Millisecond {
		return p.Latency.Round(time.Millisecond).String()
	}
	return p.Latency.Round(time.Microsecond).String()
}

func dashIfEmpty(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
