// Package resutil provides shared DNS resolution utilities
package resutil

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

// errNoSuitableAddress mirrors the unexported error string the net package
// uses when a resolved host has no addresses of the requested family.
const errNoSuitableAddress = "no suitable address found"

// Extended DNS Error info codes NetBird emits so a client can see why an answer
// looks the way it does without reading this peer's logs. They live in the RFC
// 8914 Private Use range (49152-65535) and are registered here, in one place,
// because nothing else guarantees two NetBird components pick distinct codes.
const (
	// EDENetbirdUpstreamTimeout: a DNS forwarder's upstream did not answer.
	EDENetbirdUpstreamTimeout uint16 = 49152
	// EDENetbirdUpstreamFailure: a DNS forwarder's upstream failed.
	EDENetbirdUpstreamFailure uint16 = 49153
	// EDENetbirdSoftenedNegative: the empty answer is ours, not the answering
	// resolver's. A handler that owns the name deferred this query type, and the
	// negative verdict that came back was downgraded so it cannot poison the
	// name.
	EDENetbirdSoftenedNegative uint16 = 49154
)

// AttachEDE adds an Extended DNS Error (RFC 8914) option to a message, creating
// the OPT pseudo-record if it has none. Callers must only use it toward a client
// that advertised EDNS0: per RFC 6891 an OPT must not appear otherwise.
func AttachEDE(msg *dns.Msg, code uint16, text string) {
	opt := msg.IsEdns0()
	if opt == nil {
		msg.SetEdns0(dns.DefaultMsgSize, false)
		opt = msg.IsEdns0()
	}
	opt.Option = append(opt.Option, &dns.EDNS0_EDE{InfoCode: code, ExtraText: text})
}

// GenerateRequestID creates a random 8-character hex string for request tracing.
func GenerateRequestID() string {
	bytes := make([]byte, 4)
	if _, err := rand.Read(bytes); err != nil {
		log.Errorf("generate request ID: %v", err)
		return ""
	}
	return hex.EncodeToString(bytes)
}

// IPsToRRs converts a slice of IP addresses to DNS resource records.
// IPv4 addresses become A records, IPv6 addresses become AAAA records.
func IPsToRRs(name string, ips []netip.Addr, ttl uint32) []dns.RR {
	var result []dns.RR

	for _, ip := range ips {
		if ip.Is6() {
			result = append(result, &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   name,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    ttl,
				},
				AAAA: ip.AsSlice(),
			})
		} else {
			result = append(result, &dns.A{
				Hdr: dns.RR_Header{
					Name:   name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    ttl,
				},
				A: ip.AsSlice(),
			})
		}
	}

	return result
}

// NetworkForQtype returns the network string ("ip4" or "ip6") for a DNS query type.
// Returns empty string for unsupported types.
func NetworkForQtype(qtype uint16) string {
	switch qtype {
	case dns.TypeA:
		return "ip4"
	case dns.TypeAAAA:
		return "ip6"
	default:
		return ""
	}
}

type resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// MetaKey names an annotation a handler attaches to a request to explain the
// response the chain ends up writing. The set is closed and rendered onto a
// single log line, so an unrecognized key is a typo inventing a field rather
// than a new fact.
type MetaKey string

const (
	// MetaKeyProtocol: the transport a query arrived on.
	MetaKeyProtocol MetaKey = "protocol"
	// MetaKeyUpstream: the upstream that answered.
	MetaKeyUpstream MetaKey = "upstream"
	// MetaKeyUpstreamProtocol: the transport used toward that upstream.
	MetaKeyUpstreamProtocol MetaKey = "upstream_protocol"
	// MetaKeyPeer: the routing peer whose forwarder answered.
	MetaKeyPeer MetaKey = "peer"
	// MetaKeyEDE: an Extended DNS Error carried by the answer.
	MetaKeyEDE MetaKey = "ede"
	// MetaKeyTruncated: the answer did not fit and was truncated.
	MetaKeyTruncated MetaKey = "truncated"
	// MetaKeySoftened: a negative verdict was rewritten so it cannot poison a
	// name served locally.
	MetaKeySoftened MetaKey = "softened"
	// MetaKeyDeferredBy: the handler that owned the name and stepped aside.
	MetaKeyDeferredBy MetaKey = "deferred_by"
	// MetaKeyDeferredReason: why it stepped aside.
	MetaKeyDeferredReason MetaKey = "deferred_reason"
)

// chainedWriter is implemented by ResponseWriters that carry request metadata
type chainedWriter interface {
	RequestID() string
	SetMeta(key MetaKey, value string)
}

// GetRequestID extracts a request ID from the ResponseWriter if available,
// otherwise generates a new one.
func GetRequestID(w dns.ResponseWriter) string {
	if cw, ok := w.(chainedWriter); ok {
		if id := cw.RequestID(); id != "" {
			return id
		}
	}
	return GenerateRequestID()
}

// SetMeta sets metadata on the ResponseWriter if it supports it.
func SetMeta(w dns.ResponseWriter, key MetaKey, value string) {
	if cw, ok := w.(chainedWriter); ok {
		cw.SetMeta(key, value)
	}
}

// softNegativeRequester is implemented by chain writers that can soften the
// negative verdict of the handlers a deferring handler falls through to.
type softNegativeRequester interface {
	RequestSoftNegative()
}

// RequestSoftNegative asks the handler chain to downgrade an NXDOMAIN from the
// handlers that run after the caller defers. A handler that owns a name but
// cannot answer one query type for it needs this: the resolvers it falls
// through to cannot prove the name absent, and an NXDOMAIN from them is cached
// for the name and every type under it (RFC 2308, RFC 8020), taking the
// addresses the handler does serve down with it.
func RequestSoftNegative(w dns.ResponseWriter) {
	if sn, ok := w.(softNegativeRequester); ok {
		sn.RequestSoftNegative()
	}
}

// LookupResult contains the result of an external DNS lookup
type LookupResult struct {
	IPs   []netip.Addr
	Rcode int
	Err   error // Original error for caller's logging needs
}

// LookupIP performs a DNS lookup and determines the appropriate rcode.
func LookupIP(ctx context.Context, r resolver, network, host string, qtype uint16) LookupResult {
	ips, err := r.LookupNetIP(ctx, network, host)
	if err != nil {
		return LookupResult{
			Rcode: getRcodeForError(ctx, r, host, qtype, err),
			Err:   err,
		}
	}

	// Unmap IPv4-mapped IPv6 addresses that some resolvers may return
	for i, ip := range ips {
		ips[i] = ip.Unmap()
	}

	return LookupResult{
		IPs:   ips,
		Rcode: dns.RcodeSuccess,
	}
}

func getRcodeForError(ctx context.Context, r resolver, host string, qtype uint16, err error) int {
	// The net package returns this AddrError when the host resolves but has
	// no addresses of the requested family. The domain exists, so answer
	// NODATA instead of SERVFAIL.
	var addrErr *net.AddrError
	if errors.As(err, &addrErr) && addrErr.Err == errNoSuitableAddress {
		return dns.RcodeSuccess
	}

	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) {
		return dns.RcodeServerFailure
	}

	if dnsErr.IsNotFound {
		return getRcodeForNotFound(ctx, r, host, qtype)
	}

	return dns.RcodeServerFailure
}

// getRcodeForNotFound distinguishes between NXDOMAIN (domain doesn't exist) and NODATA
// (domain exists but no records of requested type) by checking the opposite record type.
//
// musl libc (the reason we need this distinction) only queries A/AAAA pairs in getaddrinfo,
// so checking the opposite A/AAAA type is sufficient. Other record types (MX, TXT, etc.)
// are not queried by musl and don't need this handling.
func getRcodeForNotFound(ctx context.Context, r resolver, domain string, originalQtype uint16) int {
	// Try querying for a different record type to see if the domain exists
	// If the original query was for AAAA, try A. If it was for A, try AAAA.
	// This helps distinguish between NXDOMAIN and NODATA.
	var alternativeNetwork string
	switch originalQtype {
	case dns.TypeAAAA:
		alternativeNetwork = "ip4"
	case dns.TypeA:
		alternativeNetwork = "ip6"
	default:
		// Non-address types reach LookupIP only unexpectedly; without an
		// address pair to probe we cannot prove the name is absent, so answer
		// NODATA rather than a poisoning NXDOMAIN.
		return dns.RcodeSuccess
	}

	if _, err := r.LookupNetIP(ctx, alternativeNetwork, domain); err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			// Alternative query also returned not found - domain truly doesn't exist
			return dns.RcodeNameError
		}
		// Some other error (timeout, server failure, etc.) - can't determine, assume domain exists
		return dns.RcodeSuccess
	}

	// Alternative query succeeded - domain exists but has no records of this type
	return dns.RcodeSuccess
}

// RecordResolver is the host resolver surface used to forward non-address
// record queries. net.DefaultResolver satisfies it.
type RecordResolver interface {
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupNS(ctx context.Context, name string) ([]*net.NS, error)
	LookupSRV(ctx context.Context, service, proto, name string) (string, []*net.SRV, error)
	LookupCNAME(ctx context.Context, host string) (string, error)
	LookupAddr(ctx context.Context, addr string) ([]string, error)
}

// SupportedRecordQtype reports whether LookupRecords can resolve qtype. The
// set is bounded by the net.Resolver API, which exposes no way to query an
// arbitrary record type, and going around it with a raw exchange would mean
// picking nameservers ourselves instead of resolving the way the host does.
//
// Both ends read this: a DNS forwarder answers these types for the domains it
// routes, and a client uses it to tell which types are worth forwarding to a
// peer at all.
func SupportedRecordQtype(qtype uint16) bool {
	switch qtype {
	case dns.TypeMX, dns.TypeTXT, dns.TypeNS, dns.TypeSRV, dns.TypeCNAME, dns.TypePTR:
		return true
	default:
		return false
	}
}

// LookupRecords resolves a non-address DNS record type through the host
// resolver and returns the resource records and the DNS rcode. Types outside
// SupportedRecordQtype yield NODATA so that a routed name is never poisoned
// with NXDOMAIN for a type we cannot look up.
func LookupRecords(ctx context.Context, r RecordResolver, name string, qtype uint16, ttl uint32) ([]dns.RR, int) {
	fqdn := dns.Fqdn(name)

	switch qtype {
	case dns.TypeMX:
		return lookupMX(ctx, r, name, fqdn, ttl)
	case dns.TypeTXT:
		return lookupTXT(ctx, r, name, fqdn, ttl)
	case dns.TypeNS:
		return lookupNS(ctx, r, name, fqdn, ttl)
	case dns.TypeSRV:
		return lookupSRV(ctx, r, name, fqdn, ttl)
	case dns.TypeCNAME:
		return lookupCNAME(ctx, r, name, fqdn, ttl)
	case dns.TypePTR:
		return lookupPTR(ctx, r, name, fqdn, ttl)
	default:
		return nil, dns.RcodeSuccess
	}
}

func recordHeader(fqdn string, rrtype uint16, ttl uint32) dns.RR_Header {
	return dns.RR_Header{Name: fqdn, Rrtype: rrtype, Class: dns.ClassINET, Ttl: ttl}
}

func lookupMX(ctx context.Context, r RecordResolver, name, fqdn string, ttl uint32) ([]dns.RR, int) {
	recs, err := r.LookupMX(ctx, name)
	if err != nil {
		return nil, rcodeForRecordError(err)
	}
	rrs := make([]dns.RR, 0, len(recs))
	for _, mx := range recs {
		rrs = append(rrs, &dns.MX{
			Hdr:        recordHeader(fqdn, dns.TypeMX, ttl),
			Preference: mx.Pref,
			Mx:         dns.Fqdn(mx.Host),
		})
	}
	return rrs, dns.RcodeSuccess
}

func lookupTXT(ctx context.Context, r RecordResolver, name, fqdn string, ttl uint32) ([]dns.RR, int) {
	recs, err := r.LookupTXT(ctx, name)
	if err != nil {
		return nil, rcodeForRecordError(err)
	}
	rrs := make([]dns.RR, 0, len(recs))
	for _, txt := range recs {
		rrs = append(rrs, &dns.TXT{
			Hdr: recordHeader(fqdn, dns.TypeTXT, ttl),
			Txt: chunkTXT(txt),
		})
	}
	return rrs, dns.RcodeSuccess
}

func lookupNS(ctx context.Context, r RecordResolver, name, fqdn string, ttl uint32) ([]dns.RR, int) {
	recs, err := r.LookupNS(ctx, name)
	if err != nil {
		return nil, rcodeForRecordError(err)
	}
	rrs := make([]dns.RR, 0, len(recs))
	for _, ns := range recs {
		rrs = append(rrs, &dns.NS{
			Hdr: recordHeader(fqdn, dns.TypeNS, ttl),
			Ns:  dns.Fqdn(ns.Host),
		})
	}
	return rrs, dns.RcodeSuccess
}

func lookupSRV(ctx context.Context, r RecordResolver, name, fqdn string, ttl uint32) ([]dns.RR, int) {
	_, recs, err := r.LookupSRV(ctx, "", "", name)
	if err != nil {
		return nil, rcodeForRecordError(err)
	}
	rrs := make([]dns.RR, 0, len(recs))
	for _, srv := range recs {
		rrs = append(rrs, &dns.SRV{
			Hdr:      recordHeader(fqdn, dns.TypeSRV, ttl),
			Priority: srv.Priority,
			Weight:   srv.Weight,
			Port:     srv.Port,
			Target:   dns.Fqdn(srv.Target),
		})
	}
	return rrs, dns.RcodeSuccess
}

func lookupCNAME(ctx context.Context, r RecordResolver, name, fqdn string, ttl uint32) ([]dns.RR, int) {
	cname, err := r.LookupCNAME(ctx, name)
	if err != nil {
		return nil, rcodeForRecordError(err)
	}
	// LookupCNAME returns the queried name itself when the name resolves but
	// has no CNAME record; that is a NODATA result, not a CNAME.
	if strings.EqualFold(dns.Fqdn(cname), fqdn) {
		return nil, dns.RcodeSuccess
	}
	return []dns.RR{&dns.CNAME{
		Hdr:    recordHeader(fqdn, dns.TypeCNAME, ttl),
		Target: dns.Fqdn(cname),
	}}, dns.RcodeSuccess
}

func lookupPTR(ctx context.Context, r RecordResolver, name, fqdn string, ttl uint32) ([]dns.RR, int) {
	addr, ok := ptrQueryAddr(name)
	if !ok {
		return nil, dns.RcodeSuccess
	}
	names, err := r.LookupAddr(ctx, addr)
	if err != nil {
		return nil, rcodeForRecordError(err)
	}
	rrs := make([]dns.RR, 0, len(names))
	for _, n := range names {
		rrs = append(rrs, &dns.PTR{
			Hdr: recordHeader(fqdn, dns.TypePTR, ttl),
			Ptr: dns.Fqdn(n),
		})
	}
	return rrs, dns.RcodeSuccess
}

// ptrQueryAddr converts a reverse-DNS query name (in-addr.arpa or ip6.arpa)
// into the address string expected by net.Resolver.LookupAddr. It reports false
// when the name is not a well-formed reverse name.
func ptrQueryAddr(qname string) (string, bool) {
	name := strings.TrimSuffix(strings.ToLower(dns.Fqdn(qname)), ".")

	switch {
	case strings.HasSuffix(name, ".in-addr.arpa"):
		return parseInAddrArpa(strings.TrimSuffix(name, ".in-addr.arpa"))
	case strings.HasSuffix(name, ".ip6.arpa"):
		return parseIP6Arpa(strings.TrimSuffix(name, ".ip6.arpa"))
	default:
		return "", false
	}
}

// parseInAddrArpa turns the label portion of an in-addr.arpa name into an IPv4
// address string, reporting false when it is not a well-formed reverse name.
func parseInAddrArpa(labelPart string) (string, bool) {
	labels := strings.Split(labelPart, ".")
	if len(labels) != 4 {
		return "", false
	}
	slices.Reverse(labels)
	addr, err := netip.ParseAddr(strings.Join(labels, "."))
	if err != nil || !addr.Is4() {
		return "", false
	}
	return addr.String(), true
}

// parseIP6Arpa turns the nibble portion of an ip6.arpa name into an IPv6
// address string, reporting false when it is not a well-formed reverse name.
func parseIP6Arpa(nibblePart string) (string, bool) {
	nibbles := strings.Split(nibblePart, ".")
	if len(nibbles) != 32 {
		return "", false
	}
	slices.Reverse(nibbles)
	var sb strings.Builder
	for i, n := range nibbles {
		if i > 0 && i%4 == 0 {
			sb.WriteByte(':')
		}
		sb.WriteString(n)
	}
	addr, err := netip.ParseAddr(sb.String())
	if err != nil || !addr.Is6() {
		return "", false
	}
	return addr.String(), true
}

// rcodeForRecordError maps a non-address lookup error to a DNS rcode. A
// not-found result becomes NODATA rather than NXDOMAIN: net.DNSError.IsNotFound
// does not distinguish a missing name from a name that exists only with records
// of other types, so the name cannot be proven absent and must not be poisoned.
func rcodeForRecordError(err error) int {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
		return dns.RcodeSuccess
	}
	return dns.RcodeServerFailure
}

// chunkTXT splits a TXT string into character-strings no longer than 255 bytes
// so the record can be packed. The chunks form one TXT resource record.
func chunkTXT(s string) []string {
	const maxLen = 255
	if len(s) <= maxLen {
		return []string{s}
	}

	var chunks []string
	for len(s) > maxLen {
		chunks = append(chunks, s[:maxLen])
		s = s[maxLen:]
	}
	if len(s) > 0 {
		chunks = append(chunks, s)
	}
	return chunks
}

// FormatAnswers formats DNS resource records for logging.
func FormatAnswers(answers []dns.RR) string {
	if len(answers) == 0 {
		return "[]"
	}

	parts := make([]string, 0, len(answers))
	for _, rr := range answers {
		switch r := rr.(type) {
		case *dns.A:
			parts = append(parts, r.A.String())
		case *dns.AAAA:
			parts = append(parts, r.AAAA.String())
		case *dns.CNAME:
			parts = append(parts, "CNAME:"+r.Target)
		case *dns.PTR:
			parts = append(parts, "PTR:"+r.Ptr)
		default:
			parts = append(parts, dns.TypeToString[rr.Header().Rrtype])
		}
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

// StripOPT removes any OPT pseudo-RRs from the message's Extra section. Per
// RFC 6891 a responder must not include an OPT RR toward a client that did not
// advertise EDNS0.
func StripOPT(msg *dns.Msg) {
	if len(msg.Extra) == 0 {
		return
	}
	out := msg.Extra[:0]
	for _, rr := range msg.Extra {
		if _, ok := rr.(*dns.OPT); ok {
			continue
		}
		out = append(out, rr)
	}
	msg.Extra = out
}

// ExtractEDE returns the first Extended DNS Error (RFC 8914) option carried in
// the message, if present.
func ExtractEDE(msg *dns.Msg) (*dns.EDNS0_EDE, bool) {
	opt := msg.IsEdns0()
	if opt == nil {
		return nil, false
	}
	for _, o := range opt.Option {
		if ede, ok := o.(*dns.EDNS0_EDE); ok {
			return ede, true
		}
	}
	return nil, false
}
