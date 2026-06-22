package resutil

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockResolver struct {
	// results maps network ("ip4"/"ip6") to the lookup outcome.
	results map[string]mockLookup
}

type mockLookup struct {
	ips []netip.Addr
	err error
}

func (m *mockResolver) LookupNetIP(_ context.Context, network, _ string) ([]netip.Addr, error) {
	res, ok := m.results[network]
	if !ok {
		return nil, errors.New("unexpected network: " + network)
	}
	return res.ips, res.err
}

func TestLookupIP_Success(t *testing.T) {
	r := &mockResolver{results: map[string]mockLookup{
		"ip4": {ips: []netip.Addr{netip.MustParseAddr("::ffff:192.0.2.1")}},
	}}

	result := LookupIP(context.Background(), r, "ip4", "example.com.", dns.TypeA)

	assert.Equal(t, dns.RcodeSuccess, result.Rcode, "successful lookup should return NOERROR")
	require.Len(t, result.IPs, 1, "should return the resolved address")
	assert.Equal(t, netip.MustParseAddr("192.0.2.1"), result.IPs[0], "v4-mapped address should be unmapped")
}

func TestLookupIP_NoSuitableAddress(t *testing.T) {
	// The net package returns this AddrError when the host resolves but has
	// no addresses of the requested family (e.g. AAAA query for a v4-only
	// hosts file entry). The domain exists, so this is NODATA, not SERVFAIL.
	r := &mockResolver{results: map[string]mockLookup{
		"ip6": {err: &net.AddrError{Err: "no suitable address found", Addr: "example.com."}},
	}}

	result := LookupIP(context.Background(), r, "ip6", "example.com.", dns.TypeAAAA)

	assert.Equal(t, dns.RcodeSuccess, result.Rcode, "no suitable address should map to NODATA")
	assert.Empty(t, result.IPs, "NODATA response should carry no addresses")
}

// TestErrNoSuitableAddressMatchesNetPackage pins our copy of the error string
// to what the net package actually emits. A literal IP of the wrong family
// takes the same filterAddrList path as a resolved hostname, without network
// access.
func TestErrNoSuitableAddressMatchesNetPackage(t *testing.T) {
	_, err := (&net.Resolver{}).LookupNetIP(context.Background(), "ip6", "192.0.2.1")
	require.Error(t, err)

	var addrErr *net.AddrError
	require.ErrorAs(t, err, &addrErr, "wrong-family lookup should return AddrError")
	assert.Equal(t, errNoSuitableAddress, addrErr.Err, "net package error string should match our constant")
}

func TestLookupIP_OtherAddrError(t *testing.T) {
	r := &mockResolver{results: map[string]mockLookup{
		"ip4": {err: &net.AddrError{Err: "some other address problem", Addr: "example.com."}},
	}}

	result := LookupIP(context.Background(), r, "ip4", "example.com.", dns.TypeA)

	assert.Equal(t, dns.RcodeServerFailure, result.Rcode, "unrecognized AddrError should map to SERVFAIL")
}

func TestLookupIP_NotFoundNXDomain(t *testing.T) {
	r := &mockResolver{results: map[string]mockLookup{
		"ip4": {err: &net.DNSError{Err: "no such host", Name: "example.com.", IsNotFound: true}},
		"ip6": {err: &net.DNSError{Err: "no such host", Name: "example.com.", IsNotFound: true}},
	}}

	result := LookupIP(context.Background(), r, "ip4", "example.com.", dns.TypeA)

	assert.Equal(t, dns.RcodeNameError, result.Rcode, "not found for both families should map to NXDOMAIN")
}

func TestLookupIP_NotFoundNoData(t *testing.T) {
	r := &mockResolver{results: map[string]mockLookup{
		"ip6": {err: &net.DNSError{Err: "no such host", Name: "example.com.", IsNotFound: true}},
		"ip4": {ips: []netip.Addr{netip.MustParseAddr("192.0.2.1")}},
	}}

	result := LookupIP(context.Background(), r, "ip6", "example.com.", dns.TypeAAAA)

	assert.Equal(t, dns.RcodeSuccess, result.Rcode, "not found with the other family present should map to NODATA")
}

func TestLookupIP_GenericError(t *testing.T) {
	r := &mockResolver{results: map[string]mockLookup{
		"ip4": {err: errors.New("connection refused")},
	}}

	result := LookupIP(context.Background(), r, "ip4", "example.com.", dns.TypeA)

	assert.Equal(t, dns.RcodeServerFailure, result.Rcode, "generic error should map to SERVFAIL")
}

func TestLookupIP_DNSErrorNotIsNotFound(t *testing.T) {
	r := &mockResolver{results: map[string]mockLookup{
		"ip4": {err: &net.DNSError{Err: "server misbehaving", Name: "example.com.", IsTemporary: true}},
	}}

	result := LookupIP(context.Background(), r, "ip4", "example.com.", dns.TypeA)

	assert.Equal(t, dns.RcodeServerFailure, result.Rcode, "upstream failure should map to SERVFAIL")
}

func TestStripOPT(t *testing.T) {
	rm := &dns.Msg{
		Extra: []dns.RR{
			&dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}},
			&dns.A{Hdr: dns.RR_Header{Name: "x.", Rrtype: dns.TypeA}, A: net.IPv4(1, 2, 3, 4)},
		},
	}
	StripOPT(rm)
	assert.Len(t, rm.Extra, 1, "OPT should be removed, A kept")
	_, isOPT := rm.Extra[0].(*dns.OPT)
	assert.False(t, isOPT, "remaining record must not be OPT")
}

func TestExtractEDE(t *testing.T) {
	t.Run("no edns", func(t *testing.T) {
		_, ok := ExtractEDE(&dns.Msg{})
		assert.False(t, ok, "message without OPT has no EDE")
	})

	t.Run("edns without ede", func(t *testing.T) {
		rm := &dns.Msg{}
		rm.SetEdns0(4096, false)
		_, ok := ExtractEDE(rm)
		assert.False(t, ok, "OPT without EDE option returns false")
	})

	t.Run("with ede", func(t *testing.T) {
		rm := &dns.Msg{}
		opt := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
		opt.Option = append(opt.Option, &dns.EDNS0_EDE{InfoCode: 49152, ExtraText: "upstream timeout"})
		rm.Extra = append(rm.Extra, opt)

		ede, ok := ExtractEDE(rm)
		assert.True(t, ok, "EDE option should be found")
		assert.Equal(t, uint16(49152), ede.InfoCode)
		assert.Equal(t, "upstream timeout", ede.ExtraText)
	})
}
