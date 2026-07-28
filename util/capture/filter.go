package capture

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// Matcher tests whether a raw packet should be captured.
type Matcher interface {
	Match(data []byte) bool
}

// Filter selects packets by flat AND'd criteria. Useful for structured APIs
// (query params, proto fields). Implements Matcher.
type Filter struct {
	SrcIP   netip.Addr
	DstIP   netip.Addr
	Host    netip.Addr
	SrcPort uint16
	DstPort uint16
	Port    uint16
	Proto   uint8
}

// IsEmpty returns true if the filter has no criteria set.
func (f *Filter) IsEmpty() bool {
	return !f.SrcIP.IsValid() && !f.DstIP.IsValid() && !f.Host.IsValid() &&
		f.SrcPort == 0 && f.DstPort == 0 && f.Port == 0 && f.Proto == 0
}

// Match implements Matcher. All non-zero fields must match (AND).
func (f *Filter) Match(data []byte) bool {
	if f.IsEmpty() {
		return true
	}
	info, ok := parsePacketInfo(data)
	if !ok {
		return false
	}
	if f.Host.IsValid() && info.srcIP != f.Host && info.dstIP != f.Host {
		return false
	}
	if f.SrcIP.IsValid() && info.srcIP != f.SrcIP {
		return false
	}
	if f.DstIP.IsValid() && info.dstIP != f.DstIP {
		return false
	}
	if f.Proto != 0 && info.proto != f.Proto {
		return false
	}
	if f.Port != 0 && info.srcPort != f.Port && info.dstPort != f.Port {
		return false
	}
	if f.SrcPort != 0 && info.srcPort != f.SrcPort {
		return false
	}
	if f.DstPort != 0 && info.dstPort != f.DstPort {
		return false
	}
	return true
}

// exprNode evaluates a filter condition against pre-parsed packet info.
type exprNode func(info *packetInfo) bool

// exprMatcher wraps an expression tree. Parses the packet once, then walks the tree.
type exprMatcher struct {
	root exprNode
}

func (m *exprMatcher) Match(data []byte) bool {
	info, ok := parsePacketInfo(data)
	if !ok {
		return false
	}
	return m.root(&info)
}

func nodeAnd(a, b exprNode) exprNode {
	return func(info *packetInfo) bool { return a(info) && b(info) }
}

func nodeOr(a, b exprNode) exprNode {
	return func(info *packetInfo) bool { return a(info) || b(info) }
}

func nodeNot(n exprNode) exprNode {
	return func(info *packetInfo) bool { return !n(info) }
}

func nodeHost(addr netip.Addr) exprNode {
	return func(info *packetInfo) bool { return info.srcIP == addr || info.dstIP == addr }
}

func nodeSrcHost(addr netip.Addr) exprNode {
	return func(info *packetInfo) bool { return info.srcIP == addr }
}

func nodeDstHost(addr netip.Addr) exprNode {
	return func(info *packetInfo) bool { return info.dstIP == addr }
}

func nodePort(port uint16) exprNode {
	return func(info *packetInfo) bool { return info.srcPort == port || info.dstPort == port }
}

func nodeSrcPort(port uint16) exprNode {
	return func(info *packetInfo) bool { return info.srcPort == port }
}

func nodeDstPort(port uint16) exprNode {
	return func(info *packetInfo) bool { return info.dstPort == port }
}

func nodeProto(proto uint8) exprNode {
	return func(info *packetInfo) bool { return info.proto == proto }
}

func nodeFamily(family uint8) exprNode {
	return func(info *packetInfo) bool { return info.family == family }
}

func nodeNet(prefix netip.Prefix) exprNode {
	return func(info *packetInfo) bool { return prefix.Contains(info.srcIP) || prefix.Contains(info.dstIP) }
}

func nodeSrcNet(prefix netip.Prefix) exprNode {
	return func(info *packetInfo) bool { return prefix.Contains(info.srcIP) }
}

func nodeDstNet(prefix netip.Prefix) exprNode {
	return func(info *packetInfo) bool { return prefix.Contains(info.dstIP) }
}

// packetInfo holds parsed header fields for filtering and display.
type packetInfo struct {
	family  uint8
	srcIP   netip.Addr
	dstIP   netip.Addr
	proto   uint8
	srcPort uint16
	dstPort uint16
	hdrLen  int
}

func parsePacketInfo(data []byte) (packetInfo, bool) {
	if len(data) < 1 {
		return packetInfo{}, false
	}
	switch data[0] >> 4 {
	case 4:
		return parseIPv4Info(data)
	case 6:
		return parseIPv6Info(data)
	default:
		return packetInfo{}, false
	}
}

func parseIPv4Info(data []byte) (packetInfo, bool) {
	if len(data) < 20 {
		return packetInfo{}, false
	}
	ihl := int(data[0]&0x0f) * 4
	if ihl < 20 || len(data) < ihl {
		return packetInfo{}, false
	}
	info := packetInfo{
		family: 4,
		srcIP:  netip.AddrFrom4([4]byte{data[12], data[13], data[14], data[15]}),
		dstIP:  netip.AddrFrom4([4]byte{data[16], data[17], data[18], data[19]}),
		proto:  data[9],
		hdrLen: ihl,
	}
	if (info.proto == protoTCP || info.proto == protoUDP) && len(data) >= ihl+4 {
		info.srcPort = binary.BigEndian.Uint16(data[ihl:])
		info.dstPort = binary.BigEndian.Uint16(data[ihl+2:])
	}
	return info, true
}

// parseIPv6Info parses the fixed IPv6 header. It reads the Next Header field
// directly, so packets with extension headers (hop-by-hop, routing, fragment,
// etc.) will report the extension type as the protocol rather than the final
// transport protocol. This is acceptable for a debug capture tool.
func parseIPv6Info(data []byte) (packetInfo, bool) {
	if len(data) < 40 {
		return packetInfo{}, false
	}
	var src, dst [16]byte
	copy(src[:], data[8:24])
	copy(dst[:], data[24:40])
	info := packetInfo{
		family: 6,
		srcIP:  netip.AddrFrom16(src),
		dstIP:  netip.AddrFrom16(dst),
		proto:  data[6],
		hdrLen: 40,
	}
	if (info.proto == protoTCP || info.proto == protoUDP) && len(data) >= 44 {
		info.srcPort = binary.BigEndian.Uint16(data[40:])
		info.dstPort = binary.BigEndian.Uint16(data[42:])
	}
	return info, true
}

// ParseFilter parses a BPF-like filter expression and returns a Matcher.
// Returns nil Matcher for an empty expression (match all).
//
// Grammar (mirrors common tcpdump BPF syntax):
//
//	orExpr   = andExpr ("or" andExpr)*
//	andExpr  = unary ("and" unary)*
//	unary    = "not" unary | "(" orExpr ")" | term
//
//	term     = "host" IP | "src" target | "dst" target
//	         | "port" NUM | "net" PREFIX
//	         | "tcp" | "udp" | "icmp" | "icmp6"
//	         | "ip" | "ip6" | "proto" NUM
//	target   = "host" IP | "port" NUM | "net" PREFIX | IP
//
// Examples:
//
//	host 10.0.0.1 and tcp port 443
//	not port 22
//	(host 10.0.0.1 or host 10.0.0.2) and tcp
//	ip6 and icmp6
//	net 10.0.0.0/24
//	src host 10.0.0.1 or dst port 80
func ParseFilter(expr string) (Matcher, error) {
	tokens := tokenize(expr)
	if len(tokens) == 0 {
		return nil, nil //nolint:nilnil // nil Matcher means "match all"
	}

	p := &parser{tokens: tokens}
	node, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.pos < len(p.tokens) {
		return nil, fmt.Errorf("unexpected token %q at position %d", p.tokens[p.pos], p.pos)
	}
	return &exprMatcher{root: node}, nil
}

func tokenize(expr string) []string {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return nil
	}
	// Split on whitespace but keep parens as separate tokens.
	var tokens []string
	for _, field := range strings.Fields(expr) {
		tokens = append(tokens, splitParens(field)...)
	}
	return tokens
}

// splitParens splits "(foo)" into "(", "foo", ")".
func splitParens(s string) []string {
	var out []string
	for strings.HasPrefix(s, "(") {
		out = append(out, "(")
		s = s[1:]
	}
	var trail []string
	for strings.HasSuffix(s, ")") {
		trail = append(trail, ")")
		s = s[:len(s)-1]
	}
	if s != "" {
		out = append(out, s)
	}
	out = append(out, trail...)
	return out
}

type parser struct {
	tokens []string
	pos    int
}

func (p *parser) peek() string {
	if p.pos >= len(p.tokens) {
		return ""
	}
	return strings.ToLower(p.tokens[p.pos])
}

func (p *parser) next() string {
	tok := p.peek()
	if tok != "" {
		p.pos++
	}
	return tok
}

func (p *parser) expect(tok string) error {
	got := p.next()
	if got != tok {
		return fmt.Errorf("expected %q, got %q", tok, got)
	}
	return nil
}

func (p *parser) parseOr() (exprNode, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.peek() == "or" {
		p.next()
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = nodeOr(left, right)
	}
	return left, nil
}

func (p *parser) parseAnd() (exprNode, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for {
		tok := p.peek()
		if tok == "and" {
			p.next()
			right, err := p.parseUnary()
			if err != nil {
				return nil, err
			}
			left = nodeAnd(left, right)
			continue
		}
		// Implicit AND: two atoms without "and" between them.
		// Only if the next token starts an atom (not "or", ")", or EOF).
		if tok != "" && tok != "or" && tok != ")" {
			right, err := p.parseUnary()
			if err != nil {
				return nil, err
			}
			left = nodeAnd(left, right)
			continue
		}
		break
	}
	return left, nil
}

func (p *parser) parseUnary() (exprNode, error) {
	switch p.peek() {
	case "not":
		p.next()
		inner, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return nodeNot(inner), nil
	case "(":
		p.next()
		inner, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if err := p.expect(")"); err != nil {
			return nil, fmt.Errorf("unclosed parenthesis")
		}
		return inner, nil
	default:
		return p.parseAtom()
	}
}

func (p *parser) parseAtom() (exprNode, error) {
	tok := p.next()
	if tok == "" {
		return nil, fmt.Errorf("unexpected end of expression")
	}

	switch tok {
	case "host":
		addr, err := p.parseAddr()
		if err != nil {
			return nil, fmt.Errorf("host: %w", err)
		}
		return nodeHost(addr), nil

	case "port":
		port, err := p.parsePort()
		if err != nil {
			return nil, fmt.Errorf("port: %w", err)
		}
		return nodePort(port), nil

	case "net":
		prefix, err := p.parsePrefix()
		if err != nil {
			return nil, fmt.Errorf("net: %w", err)
		}
		return nodeNet(prefix), nil

	case "src":
		return p.parseDirTarget(true)

	case "dst":
		return p.parseDirTarget(false)

	case "tcp":
		return nodeProto(protoTCP), nil
	case "udp":
		return nodeProto(protoUDP), nil
	case "icmp":
		return nodeProto(protoICMP), nil
	case "icmp6":
		return nodeProto(protoICMPv6), nil
	case "ip":
		return nodeFamily(4), nil
	case "ip6":
		return nodeFamily(6), nil

	case "proto":
		raw := p.next()
		if raw == "" {
			return nil, fmt.Errorf("proto: missing number")
		}
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 || n > 255 {
			return nil, fmt.Errorf("proto: invalid number %q", raw)
		}
		return nodeProto(uint8(n)), nil

	default:
		return nil, fmt.Errorf("unknown filter keyword %q", tok)
	}
}

func (p *parser) parseDirTarget(isSrc bool) (exprNode, error) {
	tok := p.peek()
	switch tok {
	case "host":
		p.next()
		addr, err := p.parseAddr()
		if err != nil {
			return nil, err
		}
		if isSrc {
			return nodeSrcHost(addr), nil
		}
		return nodeDstHost(addr), nil

	case "port":
		p.next()
		port, err := p.parsePort()
		if err != nil {
			return nil, err
		}
		if isSrc {
			return nodeSrcPort(port), nil
		}
		return nodeDstPort(port), nil

	case "net":
		p.next()
		prefix, err := p.parsePrefix()
		if err != nil {
			return nil, err
		}
		if isSrc {
			return nodeSrcNet(prefix), nil
		}
		return nodeDstNet(prefix), nil

	default:
		// Try as bare IP: "src 10.0.0.1"
		addr, err := p.parseAddr()
		if err != nil {
			return nil, fmt.Errorf("expected host, port, net, or IP after src/dst, got %q", tok)
		}
		if isSrc {
			return nodeSrcHost(addr), nil
		}
		return nodeDstHost(addr), nil
	}
}

func (p *parser) parseAddr() (netip.Addr, error) {
	raw := p.next()
	if raw == "" {
		return netip.Addr{}, fmt.Errorf("missing IP address")
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("invalid IP %q", raw)
	}
	return addr.Unmap(), nil
}

func (p *parser) parsePort() (uint16, error) {
	raw := p.next()
	if raw == "" {
		return 0, fmt.Errorf("missing port number")
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("invalid port %q", raw)
	}
	return uint16(n), nil
}

func (p *parser) parsePrefix() (netip.Prefix, error) {
	raw := p.next()
	if raw == "" {
		return netip.Prefix{}, fmt.Errorf("missing network prefix")
	}
	prefix, err := netip.ParsePrefix(raw)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid prefix %q", raw)
	}
	return prefix, nil
}
