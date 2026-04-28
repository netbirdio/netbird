package recordwriter

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// rfc2136Writer implements RecordWriter against an authoritative DNS server
// reachable via TSIG-secured RFC 2136 dynamic update (BIND, PowerDNS, Knot,
// NSD, etc.).
//
// Unlike API-backed providers, RFC 2136 has no "list my zones" endpoint —
// the credential is scoped to a single nameserver+key pair, and the user is
// responsible for matching their server's zone authority. Zone discovery is
// done by issuing SOA queries for each apex candidate and using the first
// one the nameserver answers authoritatively.
//
// We use TCP for the UPDATE exchange because UPDATE messages routinely
// exceed 512 bytes once TSIG is appended, and TCP avoids the truncation/
// fallback dance.
type rfc2136Writer struct {
	nameserver string // host:port — passed verbatim to dns.Client.ExchangeContext
	keyName    string // FQDN form (trailing dot)
	algorithm  string // FQDN form (trailing dot), e.g. "hmac-sha256."
	tsigSecret string // base64 key material
}

func init() {
	registerRecordWriter("rfc2136", buildRFC2136Writer)
}

// buildRFC2136Writer constructs an RFC 2136 writer from a credential field
// map. Required fields mirror provider_rfc2136.go in the Lego cert path so
// a single saved credential works in both the cert path and the
// auto-configure path:
//
//	"nameserver"     — host:port (e.g. "ns1.example.com:53")
//	"tsig_algorithm" — e.g. "hmac-sha256"
//	"tsig_key"       — TSIG key name
//	"tsig_secret"    — base64 key material
//
// The user-friendly algorithm form ("hmac-sha256") is normalized to the
// FQDN form miekg/dns expects ("hmac-sha256.") here, matching what Lego
// does internally. Same for the key name.
func buildRFC2136Writer(secret map[string]string) (RecordWriter, error) {
	nameserver := secret["nameserver"]
	if nameserver == "" {
		return nil, fmt.Errorf("rfc2136 credential is missing required field %q", "nameserver")
	}
	algo := secret["tsig_algorithm"]
	if algo == "" {
		return nil, fmt.Errorf("rfc2136 credential is missing required field %q", "tsig_algorithm")
	}
	keyName := secret["tsig_key"]
	if keyName == "" {
		return nil, fmt.Errorf("rfc2136 credential is missing required field %q", "tsig_key")
	}
	tsigSecret := secret["tsig_secret"]
	if tsigSecret == "" {
		return nil, fmt.Errorf("rfc2136 credential is missing required field %q", "tsig_secret")
	}

	return &rfc2136Writer{
		nameserver: nameserver,
		keyName:    dns.Fqdn(strings.ToLower(keyName)),
		algorithm:  dns.Fqdn(strings.ToLower(algo)),
		tsigSecret: tsigSecret,
	}, nil
}

// newClient builds a TCP dns.Client preloaded with the TSIG secret. The
// secret map is keyed by the canonical (lowercase, FQDN) key name — matching
// what the server side will compute when verifying the signature.
func (w *rfc2136Writer) newClient() *dns.Client {
	return &dns.Client{
		Net:          "tcp",
		Timeout:      30 * time.Second,
		TsigSecret:   map[string]string{w.keyName: w.tsigSecret},
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
}

func (w *rfc2136Writer) WriteCNAME(ctx context.Context, fqdn, target string, ttl int) error {
	client := w.newClient()

	zone, err := w.findZone(ctx, client, fqdn)
	if err != nil {
		return err
	}

	existing, err := w.lookupCNAME(ctx, client, fqdn)
	if err != nil {
		return err
	}
	if existing != "" {
		if normalizeCNAMETarget(existing) == normalizeCNAMETarget(target) {
			return nil // idempotent
		}
		return ErrRecordExists
	}

	msg := new(dns.Msg)
	msg.SetUpdate(dns.Fqdn(zone))
	rr := &dns.CNAME{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(fqdn),
			Rrtype: dns.TypeCNAME,
			Class:  dns.ClassINET,
			Ttl:    uint32(ttl),
		},
		Target: dns.Fqdn(target),
	}
	msg.Insert([]dns.RR{rr})
	msg.SetTsig(w.keyName, w.algorithm, 300, time.Now().Unix())

	resp, _, err := client.ExchangeContext(ctx, msg, w.nameserver)
	if err != nil {
		return classifyExchangeError(err)
	}
	return mapDNSRcode(resp.Rcode)
}

func (w *rfc2136Writer) DeleteCNAME(ctx context.Context, fqdn string) error {
	client := w.newClient()

	zone, err := w.findZone(ctx, client, fqdn)
	if err != nil {
		if errors.Is(err, ErrZoneNotFound) {
			return nil // missing zone → missing record → success
		}
		return err
	}

	existing, err := w.lookupCNAME(ctx, client, fqdn)
	if err != nil {
		return err
	}
	if existing == "" {
		return nil // already absent
	}

	msg := new(dns.Msg)
	msg.SetUpdate(dns.Fqdn(zone))
	rr := &dns.CNAME{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(fqdn),
			Rrtype: dns.TypeCNAME,
			Class:  dns.ClassINET,
		},
		Target: dns.Fqdn(existing),
	}
	msg.Remove([]dns.RR{rr})
	msg.SetTsig(w.keyName, w.algorithm, 300, time.Now().Unix())

	resp, _, err := client.ExchangeContext(ctx, msg, w.nameserver)
	if err != nil {
		return classifyExchangeError(err)
	}
	return mapDNSRcode(resp.Rcode)
}

// findZone resolves which apex zone holds fqdn by issuing SOA queries for
// each apex candidate longest-first. The first candidate the nameserver
// answers with a SOA wins.
//
// SOA queries don't need TSIG (they're plain reads), but we use the same
// configured client for transport consistency. RcodeNameError on a
// candidate is normal — it just means that subdomain isn't a zone cut here.
func (w *rfc2136Writer) findZone(ctx context.Context, client *dns.Client, fqdn string) (string, error) {
	for _, candidate := range apexCandidates(fqdn) {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(candidate), dns.TypeSOA)
		resp, _, err := client.ExchangeContext(ctx, m, w.nameserver)
		if err != nil {
			// Network failure — surface immediately; we can't keep probing
			// if the server is unreachable.
			return "", classifyExchangeError(err)
		}
		if resp.Rcode == dns.RcodeSuccess && len(resp.Answer) > 0 {
			return candidate, nil
		}
		// RcodeNameError / RcodeRefused / empty answer → try next candidate.
	}
	return "", ErrZoneNotFound
}

// lookupCNAME issues a CNAME query at fqdn. Returns the existing target
// (with trailing dot stripped) if one exists, or "" if absent.
func (w *rfc2136Writer) lookupCNAME(ctx context.Context, client *dns.Client, fqdn string) (string, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(fqdn), dns.TypeCNAME)
	resp, _, err := client.ExchangeContext(ctx, m, w.nameserver)
	if err != nil {
		return "", classifyExchangeError(err)
	}
	if resp.Rcode == dns.RcodeNameError {
		return "", nil
	}
	if resp.Rcode != dns.RcodeSuccess {
		return "", mapDNSRcode(resp.Rcode)
	}
	for _, rr := range resp.Answer {
		if c, ok := rr.(*dns.CNAME); ok {
			return c.Target, nil
		}
	}
	return "", nil
}

// mapDNSRcode translates a DNS UPDATE response code to a sentinel error.
// Extracted as a pure function so it can be unit-tested without standing up
// a server.
//
// Rationale for the scope mapping: DNS doesn't have a "scope" concept the
// way Cloudflare API tokens do, but the analogous user-visible failure for
// RFC 2136 is "your TSIG key isn't allowed to write this name" — which is
// exactly what RcodeRefused (server policy denied the update) and
// RcodeNotAuth (TSIG validation failed) signal when a BIND/PowerDNS
// update-policy doesn't match. ErrInsufficientScope keeps the user-facing
// message consistent across providers.
func mapDNSRcode(rcode int) error {
	switch rcode {
	case dns.RcodeSuccess:
		return nil
	case dns.RcodeRefused, dns.RcodeNotAuth:
		return ErrInsufficientScope
	case dns.RcodeServerFailure:
		return ErrProviderUnavailable
	case dns.RcodeNXRrset, dns.RcodeYXRrset, dns.RcodeYXDomain:
		// UPDATE precondition failures — the record state on the server
		// didn't match what we asked for. For our purposes (CNAME
		// add/remove) this is best surfaced as "something else is there".
		return ErrRecordExists
	default:
		return fmt.Errorf("rfc2136 update failed with rcode %d (%s)", rcode, dns.RcodeToString[rcode])
	}
}

// classifyExchangeError maps a transport-layer error from
// dns.Client.ExchangeContext to a sentinel.
//
// TSIG verification failures on the response surface here as errors (not
// Rcodes) — specifically dns.ErrAuth ("bad authentication") when the
// server's response TSIG doesn't verify, which happens when the server
// itself rejected our TSIG and replied without a matching signature
// (BIND/PowerDNS often do this). That's a credential-scope problem, not a
// transport failure, so it maps to ErrInsufficientScope.
func classifyExchangeError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, dns.ErrAuth) {
		return fmt.Errorf("%w: %v", ErrInsufficientScope, err)
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "tsig") {
		return fmt.Errorf("%w: %v", ErrInsufficientScope, err)
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return fmt.Errorf("%w: %v", ErrProviderUnavailable, err)
	}
	return fmt.Errorf("%w: %v", ErrProviderUnavailable, err)
}
