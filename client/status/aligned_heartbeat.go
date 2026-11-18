package status

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/netbirdio/netbird/client/anonymize"
	"github.com/netbirdio/netbird/client/proto"
)

const (
	serviceManagement = "management"
	levelAligned      = "aligned"
)

// AlignedHeartbeatCorrectionOutput is one phase correction the client asked for.
type AlignedHeartbeatCorrectionOutput struct {
	Service     string    `json:"service" yaml:"service"`
	Address     string    `json:"address" yaml:"address"`
	Time        time.Time `json:"time" yaml:"time"`
	OffsetMs    int64     `json:"offsetMs" yaml:"offsetMs"`
	FromPhaseMs uint32    `json:"fromPhaseMs" yaml:"fromPhaseMs"`
	PhaseMs     uint32    `json:"wantedPhaseMs" yaml:"wantedPhaseMs"`
	Result      string    `json:"result" yaml:"result"`
}

// AlignedHeartbeatStreamOutput is the aligned heartbeat state of one stream.
type AlignedHeartbeatStreamOutput struct {
	Service           string                            `json:"service" yaml:"service"`
	Address           string                            `json:"address" yaml:"address"`
	Level             string                            `json:"level" yaml:"level"`
	PeriodSeconds     uint32                            `json:"periodSeconds" yaml:"periodSeconds"`
	PhaseMs           uint32                            `json:"phaseMs" yaml:"phaseMs"`
	LastHeartbeat     time.Time                         `json:"lastHeartbeat" yaml:"lastHeartbeat"`
	LastCorrection    *AlignedHeartbeatCorrectionOutput `json:"lastCorrection,omitempty" yaml:"lastCorrection,omitempty"`
	CorrectionBlocked bool                              `json:"correctionBlocked" yaml:"correctionBlocked"`
	BlockedInRow      uint32                            `json:"blockedInRow" yaml:"blockedInRow"`
	ClampHits         uint32                            `json:"clampHits" yaml:"clampHits"`
}

// AlignedHeartbeatOutput is the aligned heartbeat state of a mobile client.
type AlignedHeartbeatOutput struct {
	Streams     []AlignedHeartbeatStreamOutput     `json:"streams" yaml:"streams"`
	Corrections []AlignedHeartbeatCorrectionOutput `json:"corrections" yaml:"corrections"`
}

func mapAlignedHeartbeat(pb *proto.AlignedHeartbeatState) *AlignedHeartbeatOutput {
	if pb == nil {
		return nil
	}
	out := &AlignedHeartbeatOutput{}
	for _, st := range pb.GetStreams() {
		s := AlignedHeartbeatStreamOutput{
			Service:           st.GetService(),
			Address:           st.GetAddress(),
			Level:             st.GetLevel(),
			PeriodSeconds:     st.GetPeriodSeconds(),
			PhaseMs:           st.GetPhaseMillis(),
			CorrectionBlocked: st.GetCorrectionBlocked(),
			BlockedInRow:      st.GetBlockedInRow(),
			ClampHits:         st.GetClampHits(),
		}
		if st.GetLastHeartbeat() != nil {
			s.LastHeartbeat = st.GetLastHeartbeat().AsTime()
		}
		if c := st.GetLastCorrection(); c != nil {
			mapped := mapCorrection(c)
			s.LastCorrection = &mapped
		}
		out.Streams = append(out.Streams, s)
	}
	for _, c := range pb.GetCorrections() {
		out.Corrections = append(out.Corrections, mapCorrection(c))
	}
	return out
}

func mapCorrection(c *proto.AlignedHeartbeatCorrection) AlignedHeartbeatCorrectionOutput {
	out := AlignedHeartbeatCorrectionOutput{
		Service:     c.GetService(),
		Address:     c.GetAddress(),
		OffsetMs:    c.GetOffsetMillis(),
		FromPhaseMs: c.GetFromPhaseMillis(),
		PhaseMs:     c.GetWantedPhaseMillis(),
		Result:      c.GetResult(),
	}
	if c.GetTime() != nil {
		out.Time = c.GetTime().AsTime()
	}
	return out
}

// alignedHeartbeatSummary returns the stream lines for the status, empty when
// the client does not ask for the aligned heartbeat.
func (o *OutputOverview) alignedHeartbeatSummary() string {
	if o.AlignedHeartbeat == nil || len(o.AlignedHeartbeat.Streams) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("Aligned heartbeat:")
	for _, st := range o.AlignedHeartbeat.Streams {
		b.WriteString("\n  ")
		b.WriteString(streamLine(st))
	}
	b.WriteString("\n")
	return b.String()
}

func streamLine(st AlignedHeartbeatStreamOutput) string {
	line := capitalize(st.Service)
	if st.Address != "" {
		line += fmt.Sprintf(" [%s]", st.Address)
	}
	line += ": " + st.Level
	if st.Level == levelAligned {
		line += fmt.Sprintf(", period %ds, phase %d ms, last heartbeat %s",
			st.PeriodSeconds, st.PhaseMs, timeAgo(st.LastHeartbeat))
	}
	if st.Service != serviceManagement {
		line += ", last correction " + correctionText(st.LastCorrection)
	}
	if st.CorrectionBlocked {
		line += fmt.Sprintf(", corrections blocked: %d in a row not applied by the server, its clock may be off",
			st.BlockedInRow)
	}
	return line
}

func correctionText(c *AlignedHeartbeatCorrectionOutput) string {
	if c == nil {
		return "none"
	}
	return fmt.Sprintf("%s: phase %d ms to %d ms, %s", timeAgo(c.Time), c.FromPhaseMs, c.PhaseMs, c.Result)
}

// alignedHeartbeatDetail returns the latest corrections and the clamp hits
// for the detailed status, empty when the client does not ask for the aligned
// heartbeat.
func (o *OutputOverview) alignedHeartbeatDetail() string {
	if o.AlignedHeartbeat == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString("Aligned heartbeat corrections:")
	if len(o.AlignedHeartbeat.Corrections) == 0 {
		b.WriteString(" none")
	}
	for _, c := range o.AlignedHeartbeat.Corrections {
		fmt.Fprintf(&b, "\n  %s %s", c.Time.UTC().Format(time.RFC3339), capitalize(c.Service))
		if c.Address != "" {
			fmt.Fprintf(&b, " [%s]", c.Address)
		}
		fmt.Fprintf(&b, ": offset %d ms, phase %d ms to %d ms, %s", c.OffsetMs, c.FromPhaseMs, c.PhaseMs, c.Result)
	}
	b.WriteString("\nAligned heartbeat clamp hits:")
	if len(o.AlignedHeartbeat.Streams) == 0 {
		b.WriteString(" none")
	}
	for _, st := range o.AlignedHeartbeat.Streams {
		if st.Service == serviceManagement {
			continue
		}
		fmt.Fprintf(&b, "\n  %s", capitalize(st.Service))
		if st.Address != "" {
			fmt.Fprintf(&b, " [%s]", st.Address)
		}
		fmt.Fprintf(&b, ": %d, %d in a row", st.ClampHits, st.BlockedInRow)
	}
	b.WriteString("\n")
	return b.String()
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func anonymizeAlignedHeartbeat(a *anonymize.Anonymizer, hb *AlignedHeartbeatOutput) {
	if hb == nil {
		return
	}
	for i := range hb.Streams {
		hb.Streams[i].Address = anonymizeStreamAddress(a, hb.Streams[i].Address)
		if c := hb.Streams[i].LastCorrection; c != nil {
			c.Address = anonymizeStreamAddress(a, c.Address)
		}
	}
	for i := range hb.Corrections {
		hb.Corrections[i].Address = anonymizeStreamAddress(a, hb.Corrections[i].Address)
	}
}

// anonymizeStreamAddress anonymizes a stream address in any of the forms the
// streams report: a URI with a scheme, host:port, or a host alone. AnonymizeURI
// is not enough: it leaves host:port without a scheme unchanged and runs an IP
// host through the domain rules.
func anonymizeStreamAddress(a *anonymize.Anonymizer, addr string) string {
	if addr == "" {
		return addr
	}
	if !strings.Contains(addr, "://") {
		return anonymizeHostPort(a, addr)
	}
	u, err := url.Parse(addr)
	if err != nil || u.Host == "" {
		return a.AnonymizeString(addr)
	}
	u.Host = anonymizeHostPort(a, u.Host)
	return u.String()
}

func anonymizeHostPort(a *anonymize.Anonymizer, hostPort string) string {
	if host, port, err := net.SplitHostPort(hostPort); err == nil {
		return net.JoinHostPort(anonymizeHost(a, host), port)
	}
	if strings.HasPrefix(hostPort, "[") && strings.HasSuffix(hostPort, "]") {
		return "[" + anonymizeHost(a, hostPort[1:len(hostPort)-1]) + "]"
	}
	return anonymizeHost(a, hostPort)
}

func anonymizeHost(a *anonymize.Anonymizer, host string) string {
	if _, err := netip.ParseAddr(host); err == nil {
		return a.AnonymizeIPString(host)
	}
	if strings.Contains(host, ":") {
		return a.AnonymizeString(host)
	}
	return a.AnonymizeDomain(host)
}
