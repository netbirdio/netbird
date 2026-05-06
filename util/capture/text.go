package capture

import (
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// TextWriter writes human-readable one-line-per-packet summaries.
// It is not safe for concurrent use; callers must serialize access.
type TextWriter struct {
	w       io.Writer
	verbose bool
	ascii   bool
	flows   map[dirKey]uint32
}

type dirKey struct {
	src netip.AddrPort
	dst netip.AddrPort
}

// NewTextWriter creates a text formatter that writes to w.
func NewTextWriter(w io.Writer, verbose, ascii bool) *TextWriter {
	return &TextWriter{
		w:       w,
		verbose: verbose,
		ascii:   ascii,
		flows:   make(map[dirKey]uint32),
	}
}

// tag formats the fixed-width "[DIR PROTO]" prefix with right-aligned protocol.
func tag(dir Direction, proto string) string {
	return fmt.Sprintf("[%-3s %4s]", dir, proto)
}

// WritePacket formats and writes a single packet line.
func (tw *TextWriter) WritePacket(ts time.Time, data []byte, dir Direction) error {
	ts = ts.Local()
	info, ok := parsePacketInfo(data)
	if !ok {
		_, err := fmt.Fprintf(tw.w, "%s [%-3s    ?] ??? len=%d\n",
			ts.Format("15:04:05.000000"), dir, len(data))
		return err
	}

	timeStr := ts.Format("15:04:05.000000")

	var err error
	switch info.proto {
	case protoTCP:
		err = tw.writeTCP(timeStr, dir, &info, data)
	case protoUDP:
		err = tw.writeUDP(timeStr, dir, &info, data)
	case protoICMP:
		err = tw.writeICMPv4(timeStr, dir, &info, data)
	case protoICMPv6:
		err = tw.writeICMPv6(timeStr, dir, &info, data)
	default:
		var verbose string
		if tw.verbose {
			verbose = tw.verboseIP(data, info.family)
		}
		_, err = fmt.Fprintf(tw.w, "%s %s %s > %s length %d%s\n",
			timeStr, tag(dir, fmt.Sprintf("P%d", info.proto)),
			info.srcIP, info.dstIP, len(data)-info.hdrLen, verbose)
	}
	return err
}

func (tw *TextWriter) writeTCP(timeStr string, dir Direction, info *packetInfo, data []byte) error {
	tcp := &layers.TCP{}
	if err := tcp.DecodeFromBytes(data[info.hdrLen:], gopacket.NilDecodeFeedback); err != nil {
		return tw.writeFallback(timeStr, dir, "TCP", info, data)
	}

	flags := tcpFlagsStr(tcp)
	plen := len(tcp.Payload)

	// Protocol annotation
	var annotation string
	if plen > 0 {
		annotation = annotatePayload(tcp.Payload)
	}

	if !tw.verbose {
		_, err := fmt.Fprintf(tw.w, "%s %s %s:%d > %s:%d [%s] length %d%s\n",
			timeStr, tag(dir, "TCP"),
			info.srcIP, info.srcPort, info.dstIP, info.dstPort,
			flags, plen, annotation)
		if err != nil {
			return err
		}
		if tw.ascii && plen > 0 {
			return tw.writeASCII(tcp.Payload)
		}
		return nil
	}

	relSeq, relAck := tw.relativeSeqAck(info, tcp.Seq, tcp.Ack)

	var seqStr string
	if plen > 0 {
		seqStr = fmt.Sprintf(", seq %d:%d", relSeq, relSeq+uint32(plen))
	} else {
		seqStr = fmt.Sprintf(", seq %d", relSeq)
	}

	var ackStr string
	if tcp.ACK {
		ackStr = fmt.Sprintf(", ack %d", relAck)
	}

	var opts string
	if s := formatTCPOptions(tcp.Options); s != "" {
		opts = ", options [" + s + "]"
	}

	verbose := tw.verboseIP(data, info.family)

	_, err := fmt.Fprintf(tw.w, "%s %s %s:%d > %s:%d [%s]%s%s, win %d%s, length %d%s%s\n",
		timeStr, tag(dir, "TCP"),
		info.srcIP, info.srcPort, info.dstIP, info.dstPort,
		flags, seqStr, ackStr, tcp.Window, opts, plen, annotation, verbose)
	if err != nil {
		return err
	}
	if tw.ascii && plen > 0 {
		return tw.writeASCII(tcp.Payload)
	}
	return nil
}

func (tw *TextWriter) writeUDP(timeStr string, dir Direction, info *packetInfo, data []byte) error {
	udp := &layers.UDP{}
	if err := udp.DecodeFromBytes(data[info.hdrLen:], gopacket.NilDecodeFeedback); err != nil {
		return tw.writeFallback(timeStr, dir, "UDP", info, data)
	}

	plen := len(udp.Payload)

	// DNS replaces the entire line format
	if plen > 0 && isDNSPort(info.srcPort, info.dstPort) {
		if s := formatDNSPayload(udp.Payload); s != "" {
			var verbose string
			if tw.verbose {
				verbose = tw.verboseIP(data, info.family)
			}
			_, err := fmt.Fprintf(tw.w, "%s %s %s:%d > %s:%d %s%s\n",
				timeStr, tag(dir, "UDP"),
				info.srcIP, info.srcPort, info.dstIP, info.dstPort,
				s, verbose)
			return err
		}
	}

	var verbose string
	if tw.verbose {
		verbose = tw.verboseIP(data, info.family)
	}
	_, err := fmt.Fprintf(tw.w, "%s %s %s:%d > %s:%d length %d%s\n",
		timeStr, tag(dir, "UDP"),
		info.srcIP, info.srcPort, info.dstIP, info.dstPort,
		plen, verbose)
	if err != nil {
		return err
	}
	if tw.ascii && plen > 0 {
		return tw.writeASCII(udp.Payload)
	}
	return nil
}

func (tw *TextWriter) writeICMPv4(timeStr string, dir Direction, info *packetInfo, data []byte) error {
	icmp := &layers.ICMPv4{}
	if err := icmp.DecodeFromBytes(data[info.hdrLen:], gopacket.NilDecodeFeedback); err != nil {
		return tw.writeFallback(timeStr, dir, "ICMP", info, data)
	}

	var detail string
	if icmp.TypeCode.Type() == layers.ICMPv4TypeEchoRequest || icmp.TypeCode.Type() == layers.ICMPv4TypeEchoReply {
		detail = fmt.Sprintf("%s, id %d, seq %d", icmp.TypeCode.String(), icmp.Id, icmp.Seq)
	} else {
		detail = icmp.TypeCode.String()
	}

	var verbose string
	if tw.verbose {
		verbose = tw.verboseIP(data, info.family)
	}
	_, err := fmt.Fprintf(tw.w, "%s %s %s > %s %s, length %d%s\n",
		timeStr, tag(dir, "ICMP"), info.srcIP, info.dstIP, detail, len(data)-info.hdrLen, verbose)
	return err
}

func (tw *TextWriter) writeICMPv6(timeStr string, dir Direction, info *packetInfo, data []byte) error {
	icmp := &layers.ICMPv6{}
	if err := icmp.DecodeFromBytes(data[info.hdrLen:], gopacket.NilDecodeFeedback); err != nil {
		return tw.writeFallback(timeStr, dir, "ICMP", info, data)
	}

	var verbose string
	if tw.verbose {
		verbose = tw.verboseIP(data, info.family)
	}
	_, err := fmt.Fprintf(tw.w, "%s %s %s > %s %s, length %d%s\n",
		timeStr, tag(dir, "ICMP"), info.srcIP, info.dstIP, icmp.TypeCode.String(), len(data)-info.hdrLen, verbose)
	return err
}

func (tw *TextWriter) writeFallback(timeStr string, dir Direction, proto string, info *packetInfo, data []byte) error {
	_, err := fmt.Fprintf(tw.w, "%s %s %s:%d > %s:%d length %d\n",
		timeStr, tag(dir, proto),
		info.srcIP, info.srcPort, info.dstIP, info.dstPort,
		len(data)-info.hdrLen)
	return err
}

func (tw *TextWriter) verboseIP(data []byte, family uint8) string {
	return fmt.Sprintf(", ttl %d, id %d, iplen %d",
		ipTTL(data, family), ipID(data, family), len(data))
}

// relativeSeqAck returns seq/ack relative to the first seen value per direction.
func (tw *TextWriter) relativeSeqAck(info *packetInfo, seq, ack uint32) (relSeq, relAck uint32) {
	fwd := dirKey{
		src: netip.AddrPortFrom(info.srcIP, info.srcPort),
		dst: netip.AddrPortFrom(info.dstIP, info.dstPort),
	}
	rev := dirKey{
		src: netip.AddrPortFrom(info.dstIP, info.dstPort),
		dst: netip.AddrPortFrom(info.srcIP, info.srcPort),
	}

	if isn, ok := tw.flows[fwd]; ok {
		relSeq = seq - isn
	} else {
		tw.flows[fwd] = seq
	}

	if isn, ok := tw.flows[rev]; ok {
		relAck = ack - isn
	} else {
		relAck = ack
	}

	return relSeq, relAck
}

// writeASCII prints payload bytes as printable ASCII.
func (tw *TextWriter) writeASCII(payload []byte) error {
	if len(payload) == 0 {
		return nil
	}
	buf := make([]byte, len(payload))
	for i, b := range payload {
		switch {
		case b >= 0x20 && b < 0x7f:
			buf[i] = b
		case b == '\n' || b == '\r' || b == '\t':
			buf[i] = b
		default:
			buf[i] = '.'
		}
	}
	_, err := fmt.Fprintf(tw.w, "%s\n", buf)
	return err
}

// --- TCP helpers ---

func ipTTL(data []byte, family uint8) uint8 {
	if family == 4 && len(data) > 8 {
		return data[8]
	}
	if family == 6 && len(data) > 7 {
		return data[7]
	}
	return 0
}

func ipID(data []byte, family uint8) uint16 {
	if family == 4 && len(data) >= 6 {
		return binary.BigEndian.Uint16(data[4:6])
	}
	return 0
}

func tcpFlagsStr(tcp *layers.TCP) string {
	var buf [6]byte
	n := 0
	if tcp.SYN {
		buf[n] = 'S'
		n++
	}
	if tcp.FIN {
		buf[n] = 'F'
		n++
	}
	if tcp.RST {
		buf[n] = 'R'
		n++
	}
	if tcp.PSH {
		buf[n] = 'P'
		n++
	}
	if tcp.ACK {
		buf[n] = '.'
		n++
	}
	if tcp.URG {
		buf[n] = 'U'
		n++
	}
	if n == 0 {
		return "none"
	}
	return string(buf[:n])
}

func formatTCPOptions(opts []layers.TCPOption) string {
	var parts []string
	for _, opt := range opts {
		switch opt.OptionType {
		case layers.TCPOptionKindEndList:
			return strings.Join(parts, ",")
		case layers.TCPOptionKindNop:
			parts = append(parts, "nop")
		case layers.TCPOptionKindMSS:
			if len(opt.OptionData) == 2 {
				parts = append(parts, fmt.Sprintf("mss %d", binary.BigEndian.Uint16(opt.OptionData)))
			}
		case layers.TCPOptionKindWindowScale:
			if len(opt.OptionData) == 1 {
				parts = append(parts, fmt.Sprintf("wscale %d", opt.OptionData[0]))
			}
		case layers.TCPOptionKindSACKPermitted:
			parts = append(parts, "sackOK")
		case layers.TCPOptionKindSACK:
			blocks := len(opt.OptionData) / 8
			parts = append(parts, fmt.Sprintf("sack %d", blocks))
		case layers.TCPOptionKindTimestamps:
			if len(opt.OptionData) == 8 {
				tsval := binary.BigEndian.Uint32(opt.OptionData[0:4])
				tsecr := binary.BigEndian.Uint32(opt.OptionData[4:8])
				parts = append(parts, fmt.Sprintf("TS val %d ecr %d", tsval, tsecr))
			}
		}
	}
	return strings.Join(parts, ",")
}

// --- Protocol annotation ---

// annotatePayload returns a protocol annotation string for known application protocols.
func annotatePayload(payload []byte) string {
	if len(payload) < 4 {
		return ""
	}

	s := string(payload)

	// SSH banner: "SSH-2.0-OpenSSH_9.6\r\n"
	if strings.HasPrefix(s, "SSH-") {
		if end := strings.IndexByte(s, '\r'); end > 0 && end < 256 {
			return ": " + s[:end]
		}
	}

	// TLS records
	if ann := annotateTLS(payload); ann != "" {
		return ": " + ann
	}

	// HTTP request or response
	for _, method := range [...]string{"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "PATCH ", "OPTIONS ", "CONNECT "} {
		if strings.HasPrefix(s, method) {
			if end := strings.IndexByte(s, '\r'); end > 0 && end < 200 {
				return ": " + s[:end]
			}
		}
	}
	if strings.HasPrefix(s, "HTTP/") {
		if end := strings.IndexByte(s, '\r'); end > 0 && end < 200 {
			return ": " + s[:end]
		}
	}

	return ""
}

// annotateTLS returns a description for TLS handshake and alert records.
func annotateTLS(data []byte) string {
	if len(data) < 6 {
		return ""
	}

	switch data[0] {
	case 0x16:
		return annotateTLSHandshake(data)
	case 0x15:
		return annotateTLSAlert(data)
	}
	return ""
}

func annotateTLSHandshake(data []byte) string {
	if len(data) < 10 {
		return ""
	}
	switch data[5] {
	case 0x01:
		if sni := extractSNI(data); sni != "" {
			return "TLS ClientHello SNI=" + sni
		}
		return "TLS ClientHello"
	case 0x02:
		return "TLS ServerHello"
	}
	return ""
}

func annotateTLSAlert(data []byte) string {
	if len(data) < 7 {
		return ""
	}
	severity := "warning"
	if data[5] == 2 {
		severity = "fatal"
	}
	return fmt.Sprintf("TLS Alert %s %s", severity, tlsAlertDesc(data[6]))
}

func tlsAlertDesc(code byte) string {
	switch code {
	case 0:
		return "close_notify"
	case 10:
		return "unexpected_message"
	case 40:
		return "handshake_failure"
	case 42:
		return "bad_certificate"
	case 43:
		return "unsupported_certificate"
	case 44:
		return "certificate_revoked"
	case 45:
		return "certificate_expired"
	case 48:
		return "unknown_ca"
	case 49:
		return "access_denied"
	case 50:
		return "decode_error"
	case 70:
		return "protocol_version"
	case 80:
		return "internal_error"
	case 86:
		return "inappropriate_fallback"
	case 90:
		return "user_canceled"
	case 112:
		return "unrecognized_name"
	default:
		return fmt.Sprintf("alert(%d)", code)
	}
}

// extractSNI parses a TLS ClientHello and returns the SNI server name.
func extractSNI(data []byte) string {
	if len(data) < 6 || data[0] != 0x16 {
		return ""
	}
	recordLen := int(binary.BigEndian.Uint16(data[3:5]))
	handshake := data[5:]
	if len(handshake) > recordLen {
		handshake = handshake[:recordLen]
	}

	if len(handshake) < 4 || handshake[0] != 0x01 {
		return ""
	}
	hsLen := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
	body := handshake[4:]
	if len(body) > hsLen {
		body = body[:hsLen]
	}

	extPos := clientHelloExtensionsOffset(body)
	if extPos < 0 {
		return ""
	}
	return findSNIExtension(body, extPos)
}

// clientHelloExtensionsOffset returns the byte offset where extensions begin
// within the ClientHello body, or -1 if the body is too short.
func clientHelloExtensionsOffset(body []byte) int {
	if len(body) < 38 {
		return -1
	}
	pos := 34

	if pos >= len(body) {
		return -1
	}
	pos += 1 + int(body[pos]) // session ID

	if pos+2 > len(body) {
		return -1
	}
	pos += 2 + int(binary.BigEndian.Uint16(body[pos:pos+2])) // cipher suites

	if pos >= len(body) {
		return -1
	}
	pos += 1 + int(body[pos]) // compression methods

	if pos+2 > len(body) {
		return -1
	}
	return pos
}

func findSNIExtension(body []byte, pos int) string {
	extLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2
	extEnd := pos + extLen
	if extEnd > len(body) {
		extEnd = len(body)
	}

	for pos+4 <= extEnd {
		extType := binary.BigEndian.Uint16(body[pos : pos+2])
		eLen := int(binary.BigEndian.Uint16(body[pos+2 : pos+4]))
		pos += 4
		if pos+eLen > extEnd {
			break
		}
		if extType == 0 && eLen >= 5 {
			nameLen := int(binary.BigEndian.Uint16(body[pos+3 : pos+5]))
			if pos+5+nameLen <= extEnd {
				return string(body[pos+5 : pos+5+nameLen])
			}
		}
		pos += eLen
	}
	return ""
}

func isDNSPort(src, dst uint16) bool {
	return src == 53 || dst == 53 || src == 5353 || dst == 5353
}

// formatDNSPayload parses DNS and returns a tcpdump-style summary.
func formatDNSPayload(payload []byte) string {
	d := &layers.DNS{}
	if err := d.DecodeFromBytes(payload, gopacket.NilDecodeFeedback); err != nil {
		return ""
	}

	rd := ""
	if d.RD {
		rd = "+"
	}

	if !d.QR {
		return formatDNSQuery(d, rd, len(payload))
	}
	return formatDNSResponse(d, rd, len(payload))
}

func formatDNSQuery(d *layers.DNS, rd string, plen int) string {
	if len(d.Questions) == 0 {
		return fmt.Sprintf("%04x%s (%d)", d.ID, rd, plen)
	}
	q := d.Questions[0]
	return fmt.Sprintf("%04x%s %s? %s. (%d)", d.ID, rd, q.Type, q.Name, plen)
}

func formatDNSResponse(d *layers.DNS, rd string, plen int) string {
	anCount := d.ANCount
	nsCount := d.NSCount
	arCount := d.ARCount

	if d.ResponseCode != layers.DNSResponseCodeNoErr {
		return fmt.Sprintf("%04x %d/%d/%d %s (%d)", d.ID, anCount, nsCount, arCount, d.ResponseCode, plen)
	}

	if anCount > 0 && len(d.Answers) > 0 {
		rr := d.Answers[0]
		if rdata := shortRData(&rr); rdata != "" {
			return fmt.Sprintf("%04x %d/%d/%d %s %s (%d)", d.ID, anCount, nsCount, arCount, rr.Type, rdata, plen)
		}
	}

	return fmt.Sprintf("%04x %d/%d/%d (%d)", d.ID, anCount, nsCount, arCount, plen)
}

func shortRData(rr *layers.DNSResourceRecord) string {
	switch rr.Type {
	case layers.DNSTypeA, layers.DNSTypeAAAA:
		if rr.IP != nil {
			return rr.IP.String()
		}
	case layers.DNSTypeCNAME:
		if len(rr.CNAME) > 0 {
			return string(rr.CNAME) + "."
		}
	case layers.DNSTypePTR:
		if len(rr.PTR) > 0 {
			return string(rr.PTR) + "."
		}
	case layers.DNSTypeNS:
		if len(rr.NS) > 0 {
			return string(rr.NS) + "."
		}
	case layers.DNSTypeMX:
		return fmt.Sprintf("%d %s.", rr.MX.Preference, rr.MX.Name)
	case layers.DNSTypeTXT:
		if len(rr.TXTs) > 0 {
			return fmt.Sprintf("%q", string(rr.TXTs[0]))
		}
	case layers.DNSTypeSRV:
		return fmt.Sprintf("%d %d %d %s.", rr.SRV.Priority, rr.SRV.Weight, rr.SRV.Port, rr.SRV.Name)
	}
	return ""
}
