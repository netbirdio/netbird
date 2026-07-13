package resutil

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
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

func TestPtrQueryAddr(t *testing.T) {
	tests := []struct {
		name   string
		qname  string
		want   string
		wantOK bool
	}{
		{name: "ipv4", qname: "4.3.2.1.in-addr.arpa.", want: "1.2.3.4", wantOK: true},
		{name: "ipv4 no trailing dot", qname: "1.0.0.127.in-addr.arpa", want: "127.0.0.1", wantOK: true},
		{
			name:   "ipv6",
			qname:  "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
			want:   "2001:db8::1",
			wantOK: true,
		},
		{name: "ipv4 wrong label count", qname: "2.1.in-addr.arpa.", wantOK: false},
		{name: "ipv6 wrong nibble count", qname: "1.0.ip6.arpa.", wantOK: false},
		{name: "not a reverse name", qname: "example.com.", wantOK: false},
		{name: "ipv4 bad octet", qname: "4.3.2.999.in-addr.arpa.", wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := ptrQueryAddr(tt.qname)
			assert.Equal(t, tt.wantOK, ok, "parse success mismatch")
			if tt.wantOK {
				assert.Equal(t, tt.want, got, "parsed address mismatch")
			}
		})
	}
}

type mockRecordResolver struct {
	mx    []*net.MX
	txt   []string
	ns    []*net.NS
	srv   []*net.SRV
	cname string
	ptr   []string
	err   error
}

func (m *mockRecordResolver) LookupMX(context.Context, string) ([]*net.MX, error) {
	return m.mx, m.err
}
func (m *mockRecordResolver) LookupTXT(context.Context, string) ([]string, error) {
	return m.txt, m.err
}
func (m *mockRecordResolver) LookupNS(context.Context, string) ([]*net.NS, error) {
	return m.ns, m.err
}
func (m *mockRecordResolver) LookupSRV(context.Context, string, string, string) (string, []*net.SRV, error) {
	return "", m.srv, m.err
}
func (m *mockRecordResolver) LookupCNAME(context.Context, string) (string, error) {
	return m.cname, m.err
}
func (m *mockRecordResolver) LookupAddr(context.Context, string) ([]string, error) {
	return m.ptr, m.err
}

func TestLookupRecords(t *testing.T) {
	notFound := &net.DNSError{IsNotFound: true, Name: "example.com."}

	t.Run("MX success", func(t *testing.T) {
		r := &mockRecordResolver{mx: []*net.MX{{Host: "mail.example.com.", Pref: 10}}}
		rrs, rcode := LookupRecords(context.Background(), r, "example.com.", dns.TypeMX, 300)
		assert.Equal(t, dns.RcodeSuccess, rcode)
		require.Len(t, rrs, 1)
		assert.Equal(t, "mail.example.com.", rrs[0].(*dns.MX).Mx)
	})

	t.Run("TXT short string is one character-string", func(t *testing.T) {
		r := &mockRecordResolver{txt: []string{"v=spf1 -all"}}
		rrs, rcode := LookupRecords(context.Background(), r, "example.com.", dns.TypeTXT, 300)
		assert.Equal(t, dns.RcodeSuccess, rcode)
		require.Len(t, rrs, 1)
		assert.Equal(t, []string{"v=spf1 -all"}, rrs[0].(*dns.TXT).Txt)
	})

	t.Run("TXT chunks long strings", func(t *testing.T) {
		long := strings.Repeat("a", 300)
		r := &mockRecordResolver{txt: []string{long}}
		rrs, rcode := LookupRecords(context.Background(), r, "example.com.", dns.TypeTXT, 300)
		assert.Equal(t, dns.RcodeSuccess, rcode)
		require.Len(t, rrs, 1)
		txt := rrs[0].(*dns.TXT).Txt
		require.Len(t, txt, 2, "300-byte string should split into two character-strings")
		assert.Equal(t, 255, len(txt[0]))
		assert.Equal(t, 45, len(txt[1]))
	})

	t.Run("NS success", func(t *testing.T) {
		r := &mockRecordResolver{ns: []*net.NS{{Host: "ns1.example.com."}}}
		rrs, rcode := LookupRecords(context.Background(), r, "example.com.", dns.TypeNS, 300)
		assert.Equal(t, dns.RcodeSuccess, rcode)
		require.Len(t, rrs, 1)
		assert.Equal(t, "ns1.example.com.", rrs[0].(*dns.NS).Ns)
	})

	t.Run("SRV success", func(t *testing.T) {
		r := &mockRecordResolver{srv: []*net.SRV{{Target: "sip.example.com.", Port: 5060}}}
		rrs, rcode := LookupRecords(context.Background(), r, "_sip._tcp.example.com.", dns.TypeSRV, 300)
		assert.Equal(t, dns.RcodeSuccess, rcode)
		require.Len(t, rrs, 1)
		assert.Equal(t, uint16(5060), rrs[0].(*dns.SRV).Port)
	})

	t.Run("CNAME success", func(t *testing.T) {
		r := &mockRecordResolver{cname: "target.example.com."}
		rrs, rcode := LookupRecords(context.Background(), r, "www.example.com.", dns.TypeCNAME, 300)
		assert.Equal(t, dns.RcodeSuccess, rcode)
		require.Len(t, rrs, 1)
		assert.Equal(t, "target.example.com.", rrs[0].(*dns.CNAME).Target)
	})

	t.Run("CNAME equal to name is NODATA", func(t *testing.T) {
		r := &mockRecordResolver{cname: "example.com."}
		rrs, rcode := LookupRecords(context.Background(), r, "example.com.", dns.TypeCNAME, 300)
		assert.Equal(t, dns.RcodeSuccess, rcode)
		assert.Empty(t, rrs, "self-referential CNAME is NODATA")
	})

	t.Run("PTR success", func(t *testing.T) {
		r := &mockRecordResolver{ptr: []string{"host.example.com."}}
		rrs, rcode := LookupRecords(context.Background(), r, "4.3.2.1.in-addr.arpa.", dns.TypePTR, 300)
		assert.Equal(t, dns.RcodeSuccess, rcode)
		require.Len(t, rrs, 1)
		assert.Equal(t, "host.example.com.", rrs[0].(*dns.PTR).Ptr)
	})

	t.Run("PTR malformed name is NODATA", func(t *testing.T) {
		r := &mockRecordResolver{}
		rrs, rcode := LookupRecords(context.Background(), r, "example.com.", dns.TypePTR, 300)
		assert.Equal(t, dns.RcodeSuccess, rcode)
		assert.Empty(t, rrs)
	})

	t.Run("not found is NODATA never NXDOMAIN", func(t *testing.T) {
		r := &mockRecordResolver{err: notFound}
		_, rcode := LookupRecords(context.Background(), r, "example.com.", dns.TypeMX, 300)
		assert.Equal(t, dns.RcodeSuccess, rcode, "missing record must not poison the name")
	})

	t.Run("server failure maps to SERVFAIL", func(t *testing.T) {
		r := &mockRecordResolver{err: &net.DNSError{Err: "server misbehaving", IsTemporary: true}}
		_, rcode := LookupRecords(context.Background(), r, "example.com.", dns.TypeMX, 300)
		assert.Equal(t, dns.RcodeServerFailure, rcode)
	})

	t.Run("unsupported type is NODATA", func(t *testing.T) {
		r := &mockRecordResolver{}
		rrs, rcode := LookupRecords(context.Background(), r, "example.com.", dns.TypeCAA, 300)
		assert.Equal(t, dns.RcodeSuccess, rcode)
		assert.Empty(t, rrs)
	})
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
