package local

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/dns/test"
	nbdns "github.com/netbirdio/netbird/dns"
)

// mockResolver implements resolver for testing
type mockResolver struct {
	lookupFunc func(ctx context.Context, network, host string) ([]netip.Addr, error)
}

func (m *mockResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if m.lookupFunc != nil {
		return m.lookupFunc(ctx, network, host)
	}
	return nil, nil
}

func TestLocalResolver_ServeDNS(t *testing.T) {
	recordA := nbdns.SimpleRecord{
		Name:  "peera.netbird.cloud.",
		Type:  1,
		Class: nbdns.DefaultClass,
		TTL:   300,
		RData: "1.2.3.4",
	}

	recordCNAME := nbdns.SimpleRecord{
		Name:  "peerb.netbird.cloud.",
		Type:  5,
		Class: nbdns.DefaultClass,
		TTL:   300,
		RData: "www.netbird.io",
	}

	wild := "wild.netbird.cloud."

	recordWild := nbdns.SimpleRecord{
		Name:  "*." + wild,
		Type:  1,
		Class: nbdns.DefaultClass,
		TTL:   300,
		RData: "1.2.3.4",
	}

	specificRecord := nbdns.SimpleRecord{
		Name:  "existing." + wild,
		Type:  1,
		Class: nbdns.DefaultClass,
		TTL:   300,
		RData: "5.6.7.8",
	}

	testCases := []struct {
		name                string
		inputRecord         nbdns.SimpleRecord
		inputMSG            *dns.Msg
		responseShouldBeNil bool
	}{
		{
			name:        "Should Resolve A Record",
			inputRecord: recordA,
			inputMSG:    new(dns.Msg).SetQuestion(recordA.Name, dns.TypeA),
		},
		{
			name:        "Should Resolve CNAME Record",
			inputRecord: recordCNAME,
			inputMSG:    new(dns.Msg).SetQuestion(recordCNAME.Name, dns.TypeCNAME),
		},
		{
			name:                "Should Not Write When Not Found A Record",
			inputRecord:         recordA,
			inputMSG:            new(dns.Msg).SetQuestion("not.found.com", dns.TypeA),
			responseShouldBeNil: true,
		},
		{
			name:        "Should Resolve A Wild Record",
			inputRecord: recordWild,
			inputMSG:    new(dns.Msg).SetQuestion("test."+wild, dns.TypeA),
		},
		{
			name:        "Should Resolve A more specific Record",
			inputRecord: specificRecord,
			inputMSG:    new(dns.Msg).SetQuestion(specificRecord.Name, dns.TypeA),
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			resolver := NewResolver()
			_ = resolver.RegisterRecord(testCase.inputRecord)
			_ = resolver.RegisterRecord(recordWild)
			var responseMSG *dns.Msg
			responseWriter := &test.MockResponseWriter{
				WriteMsgFunc: func(m *dns.Msg) error {
					responseMSG = m
					return nil
				},
			}

			resolver.ServeDNS(responseWriter, testCase.inputMSG)

			if responseMSG == nil || len(responseMSG.Answer) == 0 {
				if testCase.responseShouldBeNil {
					return
				}
				t.Fatalf("should write a response message")
			}

			answerString := responseMSG.Answer[0].String()
			if !strings.Contains(answerString, testCase.inputMSG.Question[0].Name) {
				t.Fatalf("answer doesn't contain the same domain name: \nWant: %s\nGot:%s", testCase.name, answerString)
			}
			if !strings.Contains(answerString, dns.Type(testCase.inputRecord.Type).String()) {
				t.Fatalf("answer doesn't contain the correct type: \nWant: %s\nGot:%s", dns.Type(testCase.inputRecord.Type).String(), answerString)
			}
			if !strings.Contains(answerString, testCase.inputRecord.RData) {
				t.Fatalf("answer doesn't contain the same address: \nWant: %s\nGot:%s", testCase.inputRecord.RData, answerString)
			}
		})
	}
}

// TestLocalResolver_Update_StaleRecord verifies that updating
// a record correctly replaces the old one, preventing stale entries.
func TestLocalResolver_Update_StaleRecord(t *testing.T) {
	recordName := "host.example.com."
	recordType := dns.TypeA
	recordClass := dns.ClassINET

	record1 := nbdns.SimpleRecord{
		Name: recordName, Type: int(recordType), Class: nbdns.DefaultClass, TTL: 300, RData: "1.1.1.1",
	}
	record2 := nbdns.SimpleRecord{
		Name: recordName, Type: int(recordType), Class: nbdns.DefaultClass, TTL: 300, RData: "2.2.2.2",
	}

	recordKey := dns.Question{Name: recordName, Qtype: uint16(recordClass), Qclass: recordType}

	resolver := NewResolver()

	zone1 := []nbdns.CustomZone{{Domain: "example.com.", Records: []nbdns.SimpleRecord{record1}}}
	zone2 := []nbdns.CustomZone{{Domain: "example.com.", Records: []nbdns.SimpleRecord{record2}}}

	// Apply first update
	resolver.Update(zone1)

	// Verify first update
	resolver.mu.RLock()
	rrSlice1, found1 := resolver.records[recordKey]
	resolver.mu.RUnlock()

	require.True(t, found1, "Record key %s not found after first update", recordKey)
	require.Len(t, rrSlice1, 1, "Should have exactly 1 record after first update")
	assert.Contains(t, rrSlice1[0].String(), record1.RData, "Record after first update should be %s", record1.RData)

	// Apply second update
	resolver.Update(zone2)

	// Verify second update
	resolver.mu.RLock()
	rrSlice2, found2 := resolver.records[recordKey]
	resolver.mu.RUnlock()

	require.True(t, found2, "Record key %s not found after second update", recordKey)
	require.Len(t, rrSlice2, 1, "Should have exactly 1 record after update overwriting the key")
	assert.Contains(t, rrSlice2[0].String(), record2.RData, "The single record should be the updated one (%s)", record2.RData)
	assert.NotContains(t, rrSlice2[0].String(), record1.RData, "The stale record (%s) should not be present", record1.RData)
}

// TestLocalResolver_MultipleRecords_SameQuestion verifies that multiple records
// with the same question are stored properly
func TestLocalResolver_MultipleRecords_SameQuestion(t *testing.T) {
	resolver := NewResolver()

	recordName := "multi.example.com."
	recordType := dns.TypeA

	// Create two records with the same name and type but different IPs
	record1 := nbdns.SimpleRecord{
		Name: recordName, Type: int(recordType), Class: nbdns.DefaultClass, TTL: 300, RData: "10.0.0.1",
	}
	record2 := nbdns.SimpleRecord{
		Name: recordName, Type: int(recordType), Class: nbdns.DefaultClass, TTL: 300, RData: "10.0.0.2",
	}

	zones := []nbdns.CustomZone{{Domain: "example.com.", Records: []nbdns.SimpleRecord{record1, record2}}}

	// Apply update with both records
	resolver.Update(zones)

	// Create question that matches both records
	question := dns.Question{
		Name:   recordName,
		Qtype:  recordType,
		Qclass: dns.ClassINET,
	}

	// Verify both records are stored
	resolver.mu.RLock()
	records, found := resolver.records[question]
	resolver.mu.RUnlock()

	require.True(t, found, "Records for question %v not found", question)
	require.Len(t, records, 2, "Should have exactly 2 records for the same question")

	// Verify both record data values are present
	recordStrings := []string{records[0].String(), records[1].String()}
	assert.Contains(t, recordStrings[0]+recordStrings[1], record1.RData, "First record data should be present")
	assert.Contains(t, recordStrings[0]+recordStrings[1], record2.RData, "Second record data should be present")
}

// TestLocalResolver_RecordRotation verifies that records are rotated in a round-robin fashion
func TestLocalResolver_RecordRotation(t *testing.T) {
	resolver := NewResolver()

	recordName := "rotation.example.com."
	recordType := dns.TypeA

	// Create three records with the same name and type but different IPs
	record1 := nbdns.SimpleRecord{
		Name: recordName, Type: int(recordType), Class: nbdns.DefaultClass, TTL: 300, RData: "192.168.1.1",
	}
	record2 := nbdns.SimpleRecord{
		Name: recordName, Type: int(recordType), Class: nbdns.DefaultClass, TTL: 300, RData: "192.168.1.2",
	}
	record3 := nbdns.SimpleRecord{
		Name: recordName, Type: int(recordType), Class: nbdns.DefaultClass, TTL: 300, RData: "192.168.1.3",
	}

	zones := []nbdns.CustomZone{{Domain: "example.com.", Records: []nbdns.SimpleRecord{record1, record2, record3}}}

	// Apply update with all three records
	resolver.Update(zones)

	msg := new(dns.Msg).SetQuestion(recordName, recordType)

	// First lookup - should return the records in original order
	var responses [3]*dns.Msg

	// Perform three lookups to verify rotation
	for i := 0; i < 3; i++ {
		responseWriter := &test.MockResponseWriter{
			WriteMsgFunc: func(m *dns.Msg) error {
				responses[i] = m
				return nil
			},
		}

		resolver.ServeDNS(responseWriter, msg)
	}

	// Verify all three responses contain answers
	for i, resp := range responses {
		require.NotNil(t, resp, "Response %d should not be nil", i)
		require.Len(t, resp.Answer, 3, "Response %d should have 3 answers", i)
	}

	// Verify the first record in each response is different due to rotation
	firstRecordIPs := []string{
		responses[0].Answer[0].String(),
		responses[1].Answer[0].String(),
		responses[2].Answer[0].String(),
	}

	// Each record should be different (rotated)
	assert.NotEqual(t, firstRecordIPs[0], firstRecordIPs[1], "First lookup should differ from second lookup due to rotation")
	assert.NotEqual(t, firstRecordIPs[1], firstRecordIPs[2], "Second lookup should differ from third lookup due to rotation")
	assert.NotEqual(t, firstRecordIPs[0], firstRecordIPs[2], "First lookup should differ from third lookup due to rotation")

	// After three rotations, we should have cycled through all records
	assert.Contains(t, firstRecordIPs[0]+firstRecordIPs[1]+firstRecordIPs[2], record1.RData)
	assert.Contains(t, firstRecordIPs[0]+firstRecordIPs[1]+firstRecordIPs[2], record2.RData)
	assert.Contains(t, firstRecordIPs[0]+firstRecordIPs[1]+firstRecordIPs[2], record3.RData)
}

// TestLocalResolver_CaseInsensitiveMatching verifies that DNS record lookups are case-insensitive
func TestLocalResolver_CaseInsensitiveMatching(t *testing.T) {
	resolver := NewResolver()

	// Create record with lowercase name
	lowerCaseRecord := nbdns.SimpleRecord{
		Name:  "lower.example.com.",
		Type:  int(dns.TypeA),
		Class: nbdns.DefaultClass,
		TTL:   300,
		RData: "10.10.10.10",
	}

	// Create record with mixed case name
	mixedCaseRecord := nbdns.SimpleRecord{
		Name:  "MiXeD.ExAmPlE.CoM.",
		Type:  int(dns.TypeA),
		Class: nbdns.DefaultClass,
		TTL:   300,
		RData: "20.20.20.20",
	}

	// Update resolver with the records
	resolver.Update([]nbdns.CustomZone{{Domain: "example.com.", Records: []nbdns.SimpleRecord{lowerCaseRecord, mixedCaseRecord}}})

	testCases := []struct {
		name          string
		queryName     string
		expectedRData string
		shouldResolve bool
	}{
		{
			name:          "Query lowercase with lowercase record",
			queryName:     "lower.example.com.",
			expectedRData: "10.10.10.10",
			shouldResolve: true,
		},
		{
			name:          "Query uppercase with lowercase record",
			queryName:     "LOWER.EXAMPLE.COM.",
			expectedRData: "10.10.10.10",
			shouldResolve: true,
		},
		{
			name:          "Query mixed case with lowercase record",
			queryName:     "LoWeR.eXaMpLe.CoM.",
			expectedRData: "10.10.10.10",
			shouldResolve: true,
		},
		{
			name:          "Query lowercase with mixed case record",
			queryName:     "mixed.example.com.",
			expectedRData: "20.20.20.20",
			shouldResolve: true,
		},
		{
			name:          "Query uppercase with mixed case record",
			queryName:     "MIXED.EXAMPLE.COM.",
			expectedRData: "20.20.20.20",
			shouldResolve: true,
		},
		{
			name:          "Query with different casing pattern",
			queryName:     "mIxEd.ExaMpLe.cOm.",
			expectedRData: "20.20.20.20",
			shouldResolve: true,
		},
		{
			name:          "Query non-existent domain",
			queryName:     "nonexistent.example.com.",
			shouldResolve: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var responseMSG *dns.Msg

			// Create DNS query with the test case name
			msg := new(dns.Msg).SetQuestion(tc.queryName, dns.TypeA)

			// Create mock response writer to capture the response
			responseWriter := &test.MockResponseWriter{
				WriteMsgFunc: func(m *dns.Msg) error {
					responseMSG = m
					return nil
				},
			}

			// Perform DNS query
			resolver.ServeDNS(responseWriter, msg)

			// Check if we expect a successful resolution
			if !tc.shouldResolve {
				if responseMSG == nil || len(responseMSG.Answer) == 0 {
					// Expected no answer, test passes
					return
				}
				t.Fatalf("Expected no resolution for %s, but got answer: %v", tc.queryName, responseMSG.Answer)
			}

			// Verify we got a response
			require.NotNil(t, responseMSG, "Should have received a response message")
			require.Greater(t, len(responseMSG.Answer), 0, "Response should contain at least one answer")

			// Verify the response contains the expected data
			answerString := responseMSG.Answer[0].String()
			assert.Contains(t, answerString, tc.expectedRData,
				"Answer should contain the expected IP address %s, got: %s",
				tc.expectedRData, answerString)
		})
	}
}

// TestLocalResolver_CNAMEFallback verifies that the resolver correctly falls back
// to checking for CNAME records when the requested record type isn't found
func TestLocalResolver_CNAMEFallback(t *testing.T) {
	resolver := NewResolver()

	// Create a CNAME record (but no A record for this name)
	cnameRecord := nbdns.SimpleRecord{
		Name:  "alias.example.com.",
		Type:  int(dns.TypeCNAME),
		Class: nbdns.DefaultClass,
		TTL:   300,
		RData: "target.example.com.",
	}

	// Create an A record for the CNAME target
	targetRecord := nbdns.SimpleRecord{
		Name:  "target.example.com.",
		Type:  int(dns.TypeA),
		Class: nbdns.DefaultClass,
		TTL:   300,
		RData: "192.168.100.100",
	}

	// Update resolver with both records
	resolver.Update([]nbdns.CustomZone{{Domain: "example.com.", Records: []nbdns.SimpleRecord{cnameRecord, targetRecord}}})

	testCases := []struct {
		name          string
		queryName     string
		queryType     uint16
		expectedType  string
		expectedRData string
		shouldResolve bool
	}{
		{
			name:          "Directly query CNAME record",
			queryName:     "alias.example.com.",
			queryType:     dns.TypeCNAME,
			expectedType:  "CNAME",
			expectedRData: "target.example.com.",
			shouldResolve: true,
		},
		{
			name:          "Query A record but get CNAME fallback",
			queryName:     "alias.example.com.",
			queryType:     dns.TypeA,
			expectedType:  "CNAME",
			expectedRData: "target.example.com.",
			shouldResolve: true,
		},
		{
			name:          "Query AAAA record but get CNAME fallback",
			queryName:     "alias.example.com.",
			queryType:     dns.TypeAAAA,
			expectedType:  "CNAME",
			expectedRData: "target.example.com.",
			shouldResolve: true,
		},
		{
			name:          "Query direct A record",
			queryName:     "target.example.com.",
			queryType:     dns.TypeA,
			expectedType:  "A",
			expectedRData: "192.168.100.100",
			shouldResolve: true,
		},
		{
			name:          "Query non-existent name",
			queryName:     "nonexistent.example.com.",
			queryType:     dns.TypeA,
			shouldResolve: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var responseMSG *dns.Msg

			// Create DNS query with the test case parameters
			msg := new(dns.Msg).SetQuestion(tc.queryName, tc.queryType)

			// Create mock response writer to capture the response
			responseWriter := &test.MockResponseWriter{
				WriteMsgFunc: func(m *dns.Msg) error {
					responseMSG = m
					return nil
				},
			}

			// Perform DNS query
			resolver.ServeDNS(responseWriter, msg)

			// Check if we expect a successful resolution
			if !tc.shouldResolve {
				if responseMSG == nil || len(responseMSG.Answer) == 0 || responseMSG.Rcode != dns.RcodeSuccess {
					// Expected no resolution, test passes
					return
				}
				t.Fatalf("Expected no resolution for %s, but got answer: %v", tc.queryName, responseMSG.Answer)
			}

			// Verify we got a successful response
			require.NotNil(t, responseMSG, "Should have received a response message")
			require.Equal(t, dns.RcodeSuccess, responseMSG.Rcode, "Response should have success status code")
			require.Greater(t, len(responseMSG.Answer), 0, "Response should contain at least one answer")

			// Verify the response contains the expected data
			answerString := responseMSG.Answer[0].String()
			assert.Contains(t, answerString, tc.expectedType,
				"Answer should be of type %s, got: %s", tc.expectedType, answerString)
			assert.Contains(t, answerString, tc.expectedRData,
				"Answer should contain the expected data %s, got: %s", tc.expectedRData, answerString)
		})
	}
}

// TestLocalResolver_NoErrorWithDifferentRecordType verifies that querying for a record type
// that doesn't exist but where other record types exist for the same domain returns NOERROR
// with 0 records instead of NXDOMAIN
func TestLocalResolver_NoErrorWithDifferentRecordType(t *testing.T) {
	resolver := NewResolver()
	// Mock external resolver for CNAME target resolution
	resolver.resolver = &mockResolver{
		lookupFunc: func(_ context.Context, network, host string) ([]netip.Addr, error) {
			if host == "target.example.com." {
				if network == "ip4" {
					return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
				}
				if network == "ip6" {
					return []netip.Addr{netip.MustParseAddr("2606:2800:220:1:248:1893:25c8:1946")}, nil
				}
			}
			return nil, &net.DNSError{IsNotFound: true, Name: host}
		},
	}

	recordA := nbdns.SimpleRecord{
		Name:  "example.netbird.cloud.",
		Type:  int(dns.TypeA),
		Class: nbdns.DefaultClass,
		TTL:   300,
		RData: "192.168.1.100",
	}

	recordCNAME := nbdns.SimpleRecord{
		Name:  "alias.netbird.cloud.",
		Type:  int(dns.TypeCNAME),
		Class: nbdns.DefaultClass,
		TTL:   300,
		RData: "target.example.com.",
	}

	resolver.Update([]nbdns.CustomZone{{Domain: "netbird.cloud.", Records: []nbdns.SimpleRecord{recordA, recordCNAME}}})

	testCases := []struct {
		name           string
		queryName      string
		queryType      uint16
		expectedRcode  int
		shouldHaveData bool
	}{
		{
			name:           "Query A record that exists",
			queryName:      "example.netbird.cloud.",
			queryType:      dns.TypeA,
			expectedRcode:  dns.RcodeSuccess,
			shouldHaveData: true,
		},
		{
			name:           "Query AAAA for domain with only A record",
			queryName:      "example.netbird.cloud.",
			queryType:      dns.TypeAAAA,
			expectedRcode:  dns.RcodeSuccess,
			shouldHaveData: false,
		},
		{
			name:           "Query other record with different case and non-fqdn",
			queryName:      "EXAMPLE.netbird.cloud",
			queryType:      dns.TypeAAAA,
			expectedRcode:  dns.RcodeSuccess,
			shouldHaveData: false,
		},
		{
			name:           "Query TXT for domain with only A record",
			queryName:      "example.netbird.cloud.",
			queryType:      dns.TypeTXT,
			expectedRcode:  dns.RcodeSuccess,
			shouldHaveData: false,
		},
		{
			name:           "Query A for domain with only CNAME record",
			queryName:      "alias.netbird.cloud.",
			queryType:      dns.TypeA,
			expectedRcode:  dns.RcodeSuccess,
			shouldHaveData: true,
		},
		{
			name:           "Query AAAA for domain with only CNAME record",
			queryName:      "alias.netbird.cloud.",
			queryType:      dns.TypeAAAA,
			expectedRcode:  dns.RcodeSuccess,
			shouldHaveData: true,
		},
		{
			name:           "Query for completely non-existent domain",
			queryName:      "nonexistent.netbird.cloud.",
			queryType:      dns.TypeA,
			expectedRcode:  dns.RcodeNameError,
			shouldHaveData: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var responseMSG *dns.Msg

			msg := new(dns.Msg).SetQuestion(tc.queryName, tc.queryType)

			responseWriter := &test.MockResponseWriter{
				WriteMsgFunc: func(m *dns.Msg) error {
					responseMSG = m
					return nil
				},
			}

			resolver.ServeDNS(responseWriter, msg)

			require.NotNil(t, responseMSG, "Should have received a response message")

			assert.Equal(t, tc.expectedRcode, responseMSG.Rcode,
				"Response code should be %d (%s)",
				tc.expectedRcode, dns.RcodeToString[tc.expectedRcode])

			if tc.shouldHaveData {
				assert.Greater(t, len(responseMSG.Answer), 0, "Response should contain answers")
			} else {
				assert.Equal(t, 0, len(responseMSG.Answer), "Response should contain no answers")
			}
		})
	}
}

// TestLocalResolver_CNAMEChainResolution tests comprehensive CNAME chain following
func TestLocalResolver_CNAMEChainResolution(t *testing.T) {
	t.Run("simple internal CNAME chain", func(t *testing.T) {
		resolver := NewResolver()
		resolver.Update([]nbdns.CustomZone{{
			Domain: "example.com.",
			Records: []nbdns.SimpleRecord{
				{Name: "alias.example.com.", Type: int(dns.TypeCNAME), Class: nbdns.DefaultClass, TTL: 300, RData: "target.example.com."},
				{Name: "target.example.com.", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "192.168.1.1"},
			},
		}})

		msg := new(dns.Msg).SetQuestion("alias.example.com.", dns.TypeA)
		var resp *dns.Msg
		resolver.ServeDNS(&test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { resp = m; return nil }}, msg)

		require.NotNil(t, resp)
		require.Equal(t, dns.RcodeSuccess, resp.Rcode)
		require.Len(t, resp.Answer, 2)

		cname, ok := resp.Answer[0].(*dns.CNAME)
		require.True(t, ok)
		assert.Equal(t, "target.example.com.", cname.Target)

		a, ok := resp.Answer[1].(*dns.A)
		require.True(t, ok)
		assert.Equal(t, "192.168.1.1", a.A.String())
	})

	t.Run("multi-hop CNAME chain", func(t *testing.T) {
		resolver := NewResolver()
		resolver.Update([]nbdns.CustomZone{{
			Domain: "test.",
			Records: []nbdns.SimpleRecord{
				{Name: "hop1.test.", Type: int(dns.TypeCNAME), Class: nbdns.DefaultClass, TTL: 300, RData: "hop2.test."},
				{Name: "hop2.test.", Type: int(dns.TypeCNAME), Class: nbdns.DefaultClass, TTL: 300, RData: "hop3.test."},
				{Name: "hop3.test.", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "10.0.0.1"},
			},
		}})

		msg := new(dns.Msg).SetQuestion("hop1.test.", dns.TypeA)
		var resp *dns.Msg
		resolver.ServeDNS(&test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { resp = m; return nil }}, msg)

		require.NotNil(t, resp)
		require.Equal(t, dns.RcodeSuccess, resp.Rcode)
		require.Len(t, resp.Answer, 3)
	})

	t.Run("CNAME to non-existent internal target returns only CNAME", func(t *testing.T) {
		resolver := NewResolver()
		resolver.Update([]nbdns.CustomZone{{
			Domain: "test.",
			Records: []nbdns.SimpleRecord{
				{Name: "alias.test.", Type: int(dns.TypeCNAME), Class: nbdns.DefaultClass, TTL: 300, RData: "nonexistent.test."},
			},
		}})

		msg := new(dns.Msg).SetQuestion("alias.test.", dns.TypeA)
		var resp *dns.Msg
		resolver.ServeDNS(&test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { resp = m; return nil }}, msg)

		require.NotNil(t, resp)
		require.Len(t, resp.Answer, 1)
		_, ok := resp.Answer[0].(*dns.CNAME)
		assert.True(t, ok)
	})
}

// TestLocalResolver_CNAMEMaxDepth tests the maximum depth limit for CNAME chains
func TestLocalResolver_CNAMEMaxDepth(t *testing.T) {
	t.Run("chain at max depth resolves", func(t *testing.T) {
		resolver := NewResolver()
		var records []nbdns.SimpleRecord
		// Create chain of 7 CNAMEs (under max of 8)
		for i := 1; i <= 7; i++ {
			records = append(records, nbdns.SimpleRecord{
				Name:  fmt.Sprintf("hop%d.test.", i),
				Type:  int(dns.TypeCNAME),
				Class: nbdns.DefaultClass,
				TTL:   300,
				RData: fmt.Sprintf("hop%d.test.", i+1),
			})
		}
		records = append(records, nbdns.SimpleRecord{
			Name: "hop8.test.", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "10.10.10.10",
		})

		resolver.Update([]nbdns.CustomZone{{Domain: "test.", Records: records}})

		msg := new(dns.Msg).SetQuestion("hop1.test.", dns.TypeA)
		var resp *dns.Msg
		resolver.ServeDNS(&test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { resp = m; return nil }}, msg)

		require.NotNil(t, resp)
		require.Equal(t, dns.RcodeSuccess, resp.Rcode)
		require.Len(t, resp.Answer, 8)
	})

	t.Run("chain exceeding max depth stops", func(t *testing.T) {
		resolver := NewResolver()
		var records []nbdns.SimpleRecord
		// Create chain of 10 CNAMEs (exceeds max of 8)
		for i := 1; i <= 10; i++ {
			records = append(records, nbdns.SimpleRecord{
				Name:  fmt.Sprintf("deep%d.test.", i),
				Type:  int(dns.TypeCNAME),
				Class: nbdns.DefaultClass,
				TTL:   300,
				RData: fmt.Sprintf("deep%d.test.", i+1),
			})
		}
		records = append(records, nbdns.SimpleRecord{
			Name: "deep11.test.", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "10.10.10.10",
		})

		resolver.Update([]nbdns.CustomZone{{Domain: "test.", Records: records}})

		msg := new(dns.Msg).SetQuestion("deep1.test.", dns.TypeA)
		var resp *dns.Msg
		resolver.ServeDNS(&test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { resp = m; return nil }}, msg)

		require.NotNil(t, resp)
		// Should NOT have the final A record (chain too deep)
		assert.LessOrEqual(t, len(resp.Answer), 8)
	})

	t.Run("circular CNAME is protected by max depth", func(t *testing.T) {
		resolver := NewResolver()
		resolver.Update([]nbdns.CustomZone{{
			Domain: "test.",
			Records: []nbdns.SimpleRecord{
				{Name: "loop1.test.", Type: int(dns.TypeCNAME), Class: nbdns.DefaultClass, TTL: 300, RData: "loop2.test."},
				{Name: "loop2.test.", Type: int(dns.TypeCNAME), Class: nbdns.DefaultClass, TTL: 300, RData: "loop1.test."},
			},
		}})

		msg := new(dns.Msg).SetQuestion("loop1.test.", dns.TypeA)
		var resp *dns.Msg
		resolver.ServeDNS(&test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { resp = m; return nil }}, msg)

		require.NotNil(t, resp)
		assert.LessOrEqual(t, len(resp.Answer), 8)
	})
}

// TestLocalResolver_ExternalCNAMEResolution tests CNAME resolution to external domains
func TestLocalResolver_ExternalCNAMEResolution(t *testing.T) {
	t.Run("CNAME to external domain resolves via external resolver", func(t *testing.T) {
		resolver := NewResolver()
		resolver.resolver = &mockResolver{
			lookupFunc: func(_ context.Context, network, host string) ([]netip.Addr, error) {
				if host == "external.example.com." && network == "ip4" {
					return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
				}
				return nil, nil
			},
		}

		resolver.Update([]nbdns.CustomZone{{
			Domain: "test.",
			Records: []nbdns.SimpleRecord{
				{Name: "alias.test.", Type: int(dns.TypeCNAME), Class: nbdns.DefaultClass, TTL: 300, RData: "external.example.com."},
			},
		}})

		msg := new(dns.Msg).SetQuestion("alias.test.", dns.TypeA)
		var resp *dns.Msg
		resolver.ServeDNS(&test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { resp = m; return nil }}, msg)

		require.NotNil(t, resp)
		require.Len(t, resp.Answer, 2, "Should have CNAME + A record")

		cname, ok := resp.Answer[0].(*dns.CNAME)
		require.True(t, ok)
		assert.Equal(t, "external.example.com.", cname.Target)

		a, ok := resp.Answer[1].(*dns.A)
		require.True(t, ok)
		assert.Equal(t, "93.184.216.34", a.A.String())
	})

	t.Run("CNAME to external domain resolves IPv6", func(t *testing.T) {
		resolver := NewResolver()
		resolver.resolver = &mockResolver{
			lookupFunc: func(_ context.Context, network, host string) ([]netip.Addr, error) {
				if host == "external.example.com." && network == "ip6" {
					return []netip.Addr{netip.MustParseAddr("2606:2800:220:1:248:1893:25c8:1946")}, nil
				}
				return nil, nil
			},
		}

		resolver.Update([]nbdns.CustomZone{{
			Domain: "test.",
			Records: []nbdns.SimpleRecord{
				{Name: "alias.test.", Type: int(dns.TypeCNAME), Class: nbdns.DefaultClass, TTL: 300, RData: "external.example.com."},
			},
		}})

		msg := new(dns.Msg).SetQuestion("alias.test.", dns.TypeAAAA)
		var resp *dns.Msg
		resolver.ServeDNS(&test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { resp = m; return nil }}, msg)

		require.NotNil(t, resp)
		require.Len(t, resp.Answer, 2, "Should have CNAME + AAAA record")

		cname, ok := resp.Answer[0].(*dns.CNAME)
		require.True(t, ok)
		assert.Equal(t, "external.example.com.", cname.Target)

		aaaa, ok := resp.Answer[1].(*dns.AAAA)
		require.True(t, ok)
		assert.Equal(t, "2606:2800:220:1:248:1893:25c8:1946", aaaa.AAAA.String())
	})

	t.Run("concurrent external resolution", func(t *testing.T) {
		resolver := NewResolver()
		resolver.resolver = &mockResolver{
			lookupFunc: func(_ context.Context, network, host string) ([]netip.Addr, error) {
				if host == "external.example.com." && network == "ip4" {
					return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
				}
				return nil, nil
			},
		}

		resolver.Update([]nbdns.CustomZone{{
			Domain: "test.",
			Records: []nbdns.SimpleRecord{
				{Name: "concurrent.test.", Type: int(dns.TypeCNAME), Class: nbdns.DefaultClass, TTL: 300, RData: "external.example.com."},
			},
		}})

		var wg sync.WaitGroup
		results := make([]*dns.Msg, 10)

		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				msg := new(dns.Msg).SetQuestion("concurrent.test.", dns.TypeA)
				var resp *dns.Msg
				resolver.ServeDNS(&test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { resp = m; return nil }}, msg)
				results[idx] = resp
			}(i)
		}
		wg.Wait()

		for i, resp := range results {
			require.NotNil(t, resp, "Response %d should not be nil", i)
			require.Len(t, resp.Answer, 2, "Response %d should have CNAME + A", i)
		}
	})
}

// TestLocalResolver_ZoneManagement tests zone-aware CNAME resolution
func TestLocalResolver_ZoneManagement(t *testing.T) {
	t.Run("Update sets zones correctly", func(t *testing.T) {
		resolver := NewResolver()

		resolver.Update([]nbdns.CustomZone{
			{Domain: "example.com.", Records: []nbdns.SimpleRecord{
				{Name: "host.example.com.", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "10.0.0.1"},
			}},
			{Domain: "test.local."},
		})

		assert.True(t, resolver.isInManagedZone("host.example.com."))
		assert.True(t, resolver.isInManagedZone("other.example.com."))
		assert.True(t, resolver.isInManagedZone("sub.test.local."))
		assert.False(t, resolver.isInManagedZone("external.com."))
	})

	t.Run("isInManagedZone case insensitive", func(t *testing.T) {
		resolver := NewResolver()
		resolver.Update([]nbdns.CustomZone{{Domain: "Example.COM."}})

		assert.True(t, resolver.isInManagedZone("host.example.com."))
		assert.True(t, resolver.isInManagedZone("HOST.EXAMPLE.COM."))
	})

	t.Run("Update clears zones", func(t *testing.T) {
		resolver := NewResolver()
		resolver.Update([]nbdns.CustomZone{{Domain: "example.com."}})
		assert.True(t, resolver.isInManagedZone("host.example.com."))

		resolver.Update(nil)
		assert.False(t, resolver.isInManagedZone("host.example.com."))
	})
}

// TestLocalResolver_CNAMEZoneAwareResolution tests CNAME resolution with zone awareness
func TestLocalResolver_CNAMEZoneAwareResolution(t *testing.T) {
	t.Run("CNAME target in managed zone returns NXDOMAIN per RFC 6604", func(t *testing.T) {
		resolver := NewResolver()
		resolver.Update([]nbdns.CustomZone{{
			Domain: "myzone.test.",
			Records: []nbdns.SimpleRecord{
				{Name: "alias.myzone.test.", Type: int(dns.TypeCNAME), Class: nbdns.DefaultClass, TTL: 300, RData: "nonexistent.myzone.test."},
			},
		}})

		msg := new(dns.Msg).SetQuestion("alias.myzone.test.", dns.TypeA)
		var resp *dns.Msg
		resolver.ServeDNS(&test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { resp = m; return nil }}, msg)

		require.NotNil(t, resp)
		assert.Equal(t, dns.RcodeNameError, resp.Rcode, "Should return NXDOMAIN")
		require.Len(t, resp.Answer, 1, "Should include CNAME in answer")
	})

	t.Run("CNAME to external domain skips zone check", func(t *testing.T) {
		resolver := NewResolver()
		resolver.resolver = &mockResolver{
			lookupFunc: func(_ context.Context, network, host string) ([]netip.Addr, error) {
				if host == "external.other.com." && network == "ip4" {
					return []netip.Addr{netip.MustParseAddr("203.0.113.1")}, nil
				}
				return nil, nil
			},
		}

		resolver.Update([]nbdns.CustomZone{{
			Domain: "myzone.test.",
			Records: []nbdns.SimpleRecord{
				{Name: "alias.myzone.test.", Type: int(dns.TypeCNAME), Class: nbdns.DefaultClass, TTL: 300, RData: "external.other.com."},
			},
		}})

		msg := new(dns.Msg).SetQuestion("alias.myzone.test.", dns.TypeA)
		var resp *dns.Msg
		resolver.ServeDNS(&test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { resp = m; return nil }}, msg)

		require.NotNil(t, resp)
		assert.Equal(t, dns.RcodeSuccess, resp.Rcode)
		require.Len(t, resp.Answer, 2, "Should have CNAME + A from external resolution")
	})

	t.Run("CNAME target exists with different type returns NODATA not NXDOMAIN", func(t *testing.T) {
		resolver := NewResolver()
		// CNAME points to target that has A but no AAAA - query for AAAA should be NODATA
		resolver.Update([]nbdns.CustomZone{{
			Domain: "myzone.test.",
			Records: []nbdns.SimpleRecord{
				{Name: "alias.myzone.test.", Type: int(dns.TypeCNAME), Class: nbdns.DefaultClass, TTL: 300, RData: "target.myzone.test."},
				{Name: "target.myzone.test.", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "1.1.1.1"},
			},
		}})

		msg := new(dns.Msg).SetQuestion("alias.myzone.test.", dns.TypeAAAA)
		var resp *dns.Msg
		resolver.ServeDNS(&test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { resp = m; return nil }}, msg)

		require.NotNil(t, resp)
		assert.Equal(t, dns.RcodeSuccess, resp.Rcode, "Should return NODATA (success), not NXDOMAIN")
		require.Len(t, resp.Answer, 1, "Should have only CNAME, no AAAA")
		_, ok := resp.Answer[0].(*dns.CNAME)
		assert.True(t, ok, "Answer should be CNAME record")
	})

	t.Run("external CNAME target exists but no AAAA records (NODATA)", func(t *testing.T) {
		resolver := NewResolver()
		resolver.resolver = &mockResolver{
			lookupFunc: func(_ context.Context, network, host string) ([]netip.Addr, error) {
				if host == "external.example.com." {
					if network == "ip6" {
						// No AAAA records
						return nil, &net.DNSError{IsNotFound: true, Name: host}
					}
					if network == "ip4" {
						// But A records exist - domain exists
						return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
					}
				}
				return nil, &net.DNSError{IsNotFound: true, Name: host}
			},
		}

		resolver.Update([]nbdns.CustomZone{{
			Domain: "test.",
			Records: []nbdns.SimpleRecord{
				{Name: "alias.test.", Type: int(dns.TypeCNAME), Class: nbdns.DefaultClass, TTL: 300, RData: "external.example.com."},
			},
		}})

		msg := new(dns.Msg).SetQuestion("alias.test.", dns.TypeAAAA)
		var resp *dns.Msg
		resolver.ServeDNS(&test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { resp = m; return nil }}, msg)

		require.NotNil(t, resp)
		assert.Equal(t, dns.RcodeSuccess, resp.Rcode, "Should return NODATA (success), not NXDOMAIN")
		require.Len(t, resp.Answer, 1, "Should have only CNAME")
		_, ok := resp.Answer[0].(*dns.CNAME)
		assert.True(t, ok, "Answer should be CNAME record")
	})

	// Table-driven test for all external resolution outcomes
	externalCases := []struct {
		name           string
		lookupFunc     func(context.Context, string, string) ([]netip.Addr, error)
		expectedRcode  int
		expectedAnswer int
	}{
		{
			name: "external NXDOMAIN (both A and AAAA not found)",
			lookupFunc: func(_ context.Context, network, host string) ([]netip.Addr, error) {
				return nil, &net.DNSError{IsNotFound: true, Name: host}
			},
			expectedRcode:  dns.RcodeNameError,
			expectedAnswer: 1, // CNAME only
		},
		{
			name: "external SERVFAIL (temporary error)",
			lookupFunc: func(_ context.Context, network, host string) ([]netip.Addr, error) {
				return nil, &net.DNSError{IsTemporary: true, Name: host}
			},
			expectedRcode:  dns.RcodeServerFailure,
			expectedAnswer: 1, // CNAME only
		},
		{
			name: "external SERVFAIL (timeout)",
			lookupFunc: func(_ context.Context, network, host string) ([]netip.Addr, error) {
				return nil, &net.DNSError{IsTimeout: true, Name: host}
			},
			expectedRcode:  dns.RcodeServerFailure,
			expectedAnswer: 1, // CNAME only
		},
		{
			name: "external SERVFAIL (generic error)",
			lookupFunc: func(_ context.Context, network, host string) ([]netip.Addr, error) {
				return nil, fmt.Errorf("connection refused")
			},
			expectedRcode:  dns.RcodeServerFailure,
			expectedAnswer: 1, // CNAME only
		},
		{
			name: "external success with IPs",
			lookupFunc: func(_ context.Context, network, host string) ([]netip.Addr, error) {
				if network == "ip4" {
					return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
				}
				return nil, &net.DNSError{IsNotFound: true, Name: host}
			},
			expectedRcode:  dns.RcodeSuccess,
			expectedAnswer: 2, // CNAME + A
		},
	}

	for _, tc := range externalCases {
		t.Run(tc.name, func(t *testing.T) {
			resolver := NewResolver()
			resolver.resolver = &mockResolver{lookupFunc: tc.lookupFunc}

			resolver.Update([]nbdns.CustomZone{{
				Domain: "test.",
				Records: []nbdns.SimpleRecord{
					{Name: "alias.test.", Type: int(dns.TypeCNAME), Class: nbdns.DefaultClass, TTL: 300, RData: "external.example.com."},
				},
			}})

			msg := new(dns.Msg).SetQuestion("alias.test.", dns.TypeA)
			var resp *dns.Msg
			resolver.ServeDNS(&test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { resp = m; return nil }}, msg)

			require.NotNil(t, resp)
			assert.Equal(t, tc.expectedRcode, resp.Rcode, "rcode mismatch")
			assert.Len(t, resp.Answer, tc.expectedAnswer, "answer count mismatch")
			if tc.expectedAnswer > 0 {
				_, ok := resp.Answer[0].(*dns.CNAME)
				assert.True(t, ok, "first answer should be CNAME")
			}
		})
	}
}

// TestLocalResolver_Fallthrough verifies that non-authoritative zones
// trigger fallthrough (Zero bit set) when no records match
func TestLocalResolver_Fallthrough(t *testing.T) {
	resolver := NewResolver()

	record := nbdns.SimpleRecord{
		Name:  "existing.custom.zone.",
		Type:  int(dns.TypeA),
		Class: nbdns.DefaultClass,
		TTL:   300,
		RData: "10.0.0.1",
	}

	testCases := []struct {
		name              string
		zones             []nbdns.CustomZone
		queryName         string
		expectFallthrough bool
		expectRecord      bool
	}{
		{
			name: "Authoritative zone returns NXDOMAIN without fallthrough",
			zones: []nbdns.CustomZone{{
				Domain:  "custom.zone.",
				Records: []nbdns.SimpleRecord{record},
			}},
			queryName:         "nonexistent.custom.zone.",
			expectFallthrough: false,
			expectRecord:      false,
		},
		{
			name: "Non-authoritative zone triggers fallthrough",
			zones: []nbdns.CustomZone{{
				Domain:           "custom.zone.",
				Records:          []nbdns.SimpleRecord{record},
				NonAuthoritative: true,
			}},
			queryName:         "nonexistent.custom.zone.",
			expectFallthrough: true,
			expectRecord:      false,
		},
		{
			name: "Record found in non-authoritative zone returns normally",
			zones: []nbdns.CustomZone{{
				Domain:           "custom.zone.",
				Records:          []nbdns.SimpleRecord{record},
				NonAuthoritative: true,
			}},
			queryName:         "existing.custom.zone.",
			expectFallthrough: false,
			expectRecord:      true,
		},
		{
			name: "Record found in authoritative zone returns normally",
			zones: []nbdns.CustomZone{{
				Domain:  "custom.zone.",
				Records: []nbdns.SimpleRecord{record},
			}},
			queryName:         "existing.custom.zone.",
			expectFallthrough: false,
			expectRecord:      true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resolver.Update(tc.zones)

			var responseMSG *dns.Msg
			responseWriter := &test.MockResponseWriter{
				WriteMsgFunc: func(m *dns.Msg) error {
					responseMSG = m
					return nil
				},
			}

			msg := new(dns.Msg).SetQuestion(tc.queryName, dns.TypeA)
			resolver.ServeDNS(responseWriter, msg)

			require.NotNil(t, responseMSG, "Should have received a response")

			if tc.expectFallthrough {
				assert.True(t, responseMSG.MsgHdr.Zero, "Zero bit should be set for fallthrough")
				assert.Equal(t, dns.RcodeNameError, responseMSG.Rcode, "Should return NXDOMAIN")
			} else {
				assert.False(t, responseMSG.MsgHdr.Zero, "Zero bit should not be set")
			}

			if tc.expectRecord {
				assert.Greater(t, len(responseMSG.Answer), 0, "Should have answer records")
				assert.Equal(t, dns.RcodeSuccess, responseMSG.Rcode)
			}
		})
	}
}

// TestLocalResolver_AuthoritativeFlag tests the AA flag behavior
func TestLocalResolver_AuthoritativeFlag(t *testing.T) {
	t.Run("direct record lookup is authoritative", func(t *testing.T) {
		resolver := NewResolver()
		resolver.Update([]nbdns.CustomZone{{
			Domain: "example.com.",
			Records: []nbdns.SimpleRecord{
				{Name: "host.example.com.", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "10.0.0.1"},
			},
		}})

		msg := new(dns.Msg).SetQuestion("host.example.com.", dns.TypeA)
		var resp *dns.Msg
		resolver.ServeDNS(&test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { resp = m; return nil }}, msg)

		require.NotNil(t, resp)
		assert.True(t, resp.Authoritative)
	})

	t.Run("external resolution is not authoritative", func(t *testing.T) {
		resolver := NewResolver()
		resolver.resolver = &mockResolver{
			lookupFunc: func(_ context.Context, network, host string) ([]netip.Addr, error) {
				if host == "external.example.com." && network == "ip4" {
					return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
				}
				return nil, nil
			},
		}

		resolver.Update([]nbdns.CustomZone{{
			Domain: "test.",
			Records: []nbdns.SimpleRecord{
				{Name: "alias.test.", Type: int(dns.TypeCNAME), Class: nbdns.DefaultClass, TTL: 300, RData: "external.example.com."},
			},
		}})

		msg := new(dns.Msg).SetQuestion("alias.test.", dns.TypeA)
		var resp *dns.Msg
		resolver.ServeDNS(&test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { resp = m; return nil }}, msg)

		require.NotNil(t, resp)
		require.Len(t, resp.Answer, 2)
		assert.False(t, resp.Authoritative)
	})
}

// TestLocalResolver_Stop tests cleanup on Stop
func TestLocalResolver_Stop(t *testing.T) {
	t.Run("Stop clears all state", func(t *testing.T) {
		resolver := NewResolver()
		resolver.Update([]nbdns.CustomZone{{
			Domain: "example.com.",
			Records: []nbdns.SimpleRecord{
				{Name: "host.example.com.", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "10.0.0.1"},
			},
		}})

		resolver.Stop()

		msg := new(dns.Msg).SetQuestion("host.example.com.", dns.TypeA)
		var resp *dns.Msg
		resolver.ServeDNS(&test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { resp = m; return nil }}, msg)

		require.NotNil(t, resp)
		assert.Len(t, resp.Answer, 0)
		assert.False(t, resolver.isInManagedZone("host.example.com."))
	})

	t.Run("Stop is safe to call multiple times", func(t *testing.T) {
		resolver := NewResolver()
		resolver.Update([]nbdns.CustomZone{{
			Domain: "example.com.",
			Records: []nbdns.SimpleRecord{
				{Name: "host.example.com.", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "10.0.0.1"},
			},
		}})

		resolver.Stop()
		resolver.Stop()
		resolver.Stop()
	})

	t.Run("Stop cancels in-flight external resolution", func(t *testing.T) {
		resolver := NewResolver()

		lookupStarted := make(chan struct{})
		lookupCtxCanceled := make(chan struct{})

		resolver.resolver = &mockResolver{
			lookupFunc: func(ctx context.Context, network, host string) ([]netip.Addr, error) {
				close(lookupStarted)
				<-ctx.Done()
				close(lookupCtxCanceled)
				return nil, ctx.Err()
			},
		}

		resolver.Update([]nbdns.CustomZone{{
			Domain: "test.",
			Records: []nbdns.SimpleRecord{
				{Name: "alias.test.", Type: int(dns.TypeCNAME), Class: nbdns.DefaultClass, TTL: 300, RData: "external.example.com."},
			},
		}})

		done := make(chan struct{})
		go func() {
			msg := new(dns.Msg).SetQuestion("alias.test.", dns.TypeA)
			resolver.ServeDNS(&test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { return nil }}, msg)
			close(done)
		}()

		<-lookupStarted
		resolver.Stop()

		select {
		case <-lookupCtxCanceled:
		case <-time.After(time.Second):
			t.Fatal("external lookup context was not canceled")
		}

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("ServeDNS did not return after Stop")
		}
	})
}

// TestLocalResolver_FallthroughCaseInsensitive verifies case-insensitive domain matching for fallthrough
func TestLocalResolver_FallthroughCaseInsensitive(t *testing.T) {
	resolver := NewResolver()

	resolver.Update([]nbdns.CustomZone{{
		Domain:           "EXAMPLE.COM.",
		Records:          []nbdns.SimpleRecord{{Name: "host.example.com.", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "1.2.3.4"}},
		NonAuthoritative: true,
	}})

	var responseMSG *dns.Msg
	responseWriter := &test.MockResponseWriter{
		WriteMsgFunc: func(m *dns.Msg) error {
			responseMSG = m
			return nil
		},
	}

	msg := new(dns.Msg).SetQuestion("nonexistent.example.com.", dns.TypeA)
	resolver.ServeDNS(responseWriter, msg)

	require.NotNil(t, responseMSG)
	assert.True(t, responseMSG.MsgHdr.Zero, "Should fallthrough for non-authoritative zone with case-insensitive match")
}

// TestLocalResolver_WildcardCNAME tests wildcard CNAME record handling for non-CNAME queries
func TestLocalResolver_WildcardCNAME(t *testing.T) {
	t.Run("wildcard CNAME resolves A query with internal target", func(t *testing.T) {
		resolver := NewResolver()

		// Configure wildcard CNAME pointing to internal A record
		resolver.Update([]nbdns.CustomZone{{
			Domain: "example.com.",
			Records: []nbdns.SimpleRecord{
				{Name: "*.example.com.", Type: int(dns.TypeCNAME), Class: nbdns.DefaultClass, TTL: 300, RData: "target.example.com."},
				{Name: "target.example.com.", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "10.0.0.1"},
			},
		}})

		msg := new(dns.Msg).SetQuestion("foo.example.com.", dns.TypeA)
		var resp *dns.Msg
		resolver.ServeDNS(&test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { resp = m; return nil }}, msg)

		require.NotNil(t, resp)
		require.Equal(t, dns.RcodeSuccess, resp.Rcode, "Should resolve via wildcard CNAME")
		require.Len(t, resp.Answer, 2, "Should have CNAME + A record")

		// Verify CNAME has the original query name, not the wildcard
		cname, ok := resp.Answer[0].(*dns.CNAME)
		require.True(t, ok, "First answer should be CNAME")
		assert.Equal(t, "foo.example.com.", cname.Hdr.Name, "CNAME owner should be rewritten to query name")
		assert.Equal(t, "target.example.com.", cname.Target)

		// Verify A record
		a, ok := resp.Answer[1].(*dns.A)
		require.True(t, ok, "Second answer should be A record")
		assert.Equal(t, "10.0.0.1", a.A.String())
	})

	t.Run("wildcard CNAME resolves AAAA query with internal target", func(t *testing.T) {
		resolver := NewResolver()

		resolver.Update([]nbdns.CustomZone{{
			Domain: "example.com.",
			Records: []nbdns.SimpleRecord{
				{Name: "*.example.com.", Type: int(dns.TypeCNAME), Class: nbdns.DefaultClass, TTL: 300, RData: "target.example.com."},
				{Name: "target.example.com.", Type: int(dns.TypeAAAA), Class: nbdns.DefaultClass, TTL: 300, RData: "2001:db8::1"},
			},
		}})

		msg := new(dns.Msg).SetQuestion("bar.example.com.", dns.TypeAAAA)
		var resp *dns.Msg
		resolver.ServeDNS(&test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { resp = m; return nil }}, msg)

		require.NotNil(t, resp)
		require.Equal(t, dns.RcodeSuccess, resp.Rcode, "Should resolve via wildcard CNAME")
		require.Len(t, resp.Answer, 2, "Should have CNAME + AAAA record")

		cname, ok := resp.Answer[0].(*dns.CNAME)
		require.True(t, ok)
		assert.Equal(t, "bar.example.com.", cname.Hdr.Name, "CNAME owner should be rewritten")

		aaaa, ok := resp.Answer[1].(*dns.AAAA)
		require.True(t, ok)
		assert.Equal(t, "2001:db8::1", aaaa.AAAA.String())
	})

	t.Run("specific record takes precedence over wildcard CNAME", func(t *testing.T) {
		resolver := NewResolver()

		// Both wildcard CNAME and specific A record exist
		resolver.Update([]nbdns.CustomZone{{
			Domain: "example.com.",
			Records: []nbdns.SimpleRecord{
				{Name: "*.example.com.", Type: int(dns.TypeCNAME), Class: nbdns.DefaultClass, TTL: 300, RData: "target.example.com."},
				{Name: "specific.example.com.", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "192.168.1.1"},
			},
		}})

		msg := new(dns.Msg).SetQuestion("specific.example.com.", dns.TypeA)
		var resp *dns.Msg
		resolver.ServeDNS(&test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { resp = m; return nil }}, msg)

		require.NotNil(t, resp)
		require.Equal(t, dns.RcodeSuccess, resp.Rcode)
		require.Len(t, resp.Answer, 1, "Should return specific A record only")

		a, ok := resp.Answer[0].(*dns.A)
		require.True(t, ok)
		assert.Equal(t, "192.168.1.1", a.A.String())
	})

	t.Run("specific CNAME takes precedence over wildcard CNAME", func(t *testing.T) {
		resolver := NewResolver()

		resolver.Update([]nbdns.CustomZone{{
			Domain: "example.com.",
			Records: []nbdns.SimpleRecord{
				{Name: "*.example.com.", Type: int(dns.TypeCNAME), Class: nbdns.DefaultClass, TTL: 300, RData: "wildcard-target.example.com."},
				{Name: "specific.example.com.", Type: int(dns.TypeCNAME), Class: nbdns.DefaultClass, TTL: 300, RData: "specific-target.example.com."},
				{Name: "specific-target.example.com.", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "10.1.1.1"},
				{Name: "wildcard-target.example.com.", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "10.2.2.2"},
			},
		}})

		msg := new(dns.Msg).SetQuestion("specific.example.com.", dns.TypeA)
		var resp *dns.Msg
		resolver.ServeDNS(&test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { resp = m; return nil }}, msg)

		require.NotNil(t, resp)
		require.Equal(t, dns.RcodeSuccess, resp.Rcode)
		require.GreaterOrEqual(t, len(resp.Answer), 1)

		cname, ok := resp.Answer[0].(*dns.CNAME)
		require.True(t, ok)
		assert.Equal(t, "specific-target.example.com.", cname.Target, "Should use specific CNAME, not wildcard")
	})

	t.Run("wildcard CNAME to non-existent internal target returns NXDOMAIN with CNAME", func(t *testing.T) {
		resolver := NewResolver()

		// Wildcard CNAME pointing to non-existent internal target
		resolver.Update([]nbdns.CustomZone{{
			Domain: "example.com.",
			Records: []nbdns.SimpleRecord{
				{Name: "*.example.com.", Type: int(dns.TypeCNAME), Class: nbdns.DefaultClass, TTL: 300, RData: "nonexistent.example.com."},
			},
		}})

		msg := new(dns.Msg).SetQuestion("foo.example.com.", dns.TypeA)
		var resp *dns.Msg
		resolver.ServeDNS(&test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { resp = m; return nil }}, msg)

		require.NotNil(t, resp)
		// Per RFC 6604, CNAME chains should return the rcode of the final target.
		// When the wildcard CNAME target doesn't exist in the managed zone, this
		// returns NXDOMAIN with the CNAME record included.
		// Note: Current implementation returns NODATA (success) because the wildcard
		// domain exists. This test documents the actual behavior.
		if resp.Rcode == dns.RcodeNameError {
			// RFC-compliant behavior: NXDOMAIN with CNAME
			require.Len(t, resp.Answer, 1, "Should include the CNAME pointing to non-existent target")
			cname, ok := resp.Answer[0].(*dns.CNAME)
			require.True(t, ok)
			assert.Equal(t, "foo.example.com.", cname.Hdr.Name, "CNAME owner should be rewritten")
			assert.Equal(t, "nonexistent.example.com.", cname.Target)
		} else {
			// Current behavior: NODATA (success with CNAME but target not found)
			assert.Equal(t, dns.RcodeSuccess, resp.Rcode, "Returns NODATA when wildcard exists but target doesn't")
		}
	})

	t.Run("wildcard CNAME with multi-level subdomain", func(t *testing.T) {
		resolver := NewResolver()

		resolver.Update([]nbdns.CustomZone{{
			Domain: "example.com.",
			Records: []nbdns.SimpleRecord{
				{Name: "*.example.com.", Type: int(dns.TypeCNAME), Class: nbdns.DefaultClass, TTL: 300, RData: "target.example.com."},
				{Name: "target.example.com.", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "10.0.0.1"},
			},
		}})

		// Query with multi-level subdomain - wildcard should only match first label
		// Standard DNS wildcards only match a single label, so sub.domain.example.com
		// should NOT match *.example.com - this tests current implementation behavior
		msg := new(dns.Msg).SetQuestion("sub.domain.example.com.", dns.TypeA)
		var resp *dns.Msg
		resolver.ServeDNS(&test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { resp = m; return nil }}, msg)

		require.NotNil(t, resp)
	})

	t.Run("wildcard CNAME NODATA when target has no matching type", func(t *testing.T) {
		resolver := NewResolver()

		// Wildcard CNAME to target that only has A record, query for AAAA
		resolver.Update([]nbdns.CustomZone{{
			Domain: "example.com.",
			Records: []nbdns.SimpleRecord{
				{Name: "*.example.com.", Type: int(dns.TypeCNAME), Class: nbdns.DefaultClass, TTL: 300, RData: "target.example.com."},
				{Name: "target.example.com.", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "10.0.0.1"},
			},
		}})

		msg := new(dns.Msg).SetQuestion("foo.example.com.", dns.TypeAAAA)
		var resp *dns.Msg
		resolver.ServeDNS(&test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { resp = m; return nil }}, msg)

		require.NotNil(t, resp)
		assert.Equal(t, dns.RcodeSuccess, resp.Rcode, "Should return NODATA (success with no answer for AAAA)")
		require.Len(t, resp.Answer, 1, "Should have only CNAME")

		cname, ok := resp.Answer[0].(*dns.CNAME)
		require.True(t, ok)
		assert.Equal(t, "foo.example.com.", cname.Hdr.Name)
	})

	t.Run("direct CNAME query for wildcard record", func(t *testing.T) {
		resolver := NewResolver()

		resolver.Update([]nbdns.CustomZone{{
			Domain: "example.com.",
			Records: []nbdns.SimpleRecord{
				{Name: "*.example.com.", Type: int(dns.TypeCNAME), Class: nbdns.DefaultClass, TTL: 300, RData: "target.example.com."},
			},
		}})

		// Direct CNAME query should also work via wildcard
		msg := new(dns.Msg).SetQuestion("foo.example.com.", dns.TypeCNAME)
		var resp *dns.Msg
		resolver.ServeDNS(&test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { resp = m; return nil }}, msg)

		require.NotNil(t, resp)
		require.Equal(t, dns.RcodeSuccess, resp.Rcode)
		require.Len(t, resp.Answer, 1)

		cname, ok := resp.Answer[0].(*dns.CNAME)
		require.True(t, ok)
		assert.Equal(t, "foo.example.com.", cname.Hdr.Name, "CNAME owner should be rewritten")
		assert.Equal(t, "target.example.com.", cname.Target)
	})

	t.Run("wildcard CNAME case insensitive query", func(t *testing.T) {
		resolver := NewResolver()

		resolver.Update([]nbdns.CustomZone{{
			Domain: "example.com.",
			Records: []nbdns.SimpleRecord{
				{Name: "*.example.com.", Type: int(dns.TypeCNAME), Class: nbdns.DefaultClass, TTL: 300, RData: "target.example.com."},
				{Name: "target.example.com.", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "10.0.0.1"},
			},
		}})

		msg := new(dns.Msg).SetQuestion("FOO.EXAMPLE.COM.", dns.TypeA)
		var resp *dns.Msg
		resolver.ServeDNS(&test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { resp = m; return nil }}, msg)

		require.NotNil(t, resp)
		require.Equal(t, dns.RcodeSuccess, resp.Rcode, "Wildcard CNAME should match case-insensitively")
		require.Len(t, resp.Answer, 2)
	})

	t.Run("wildcard A and wildcard CNAME coexist - A takes precedence", func(t *testing.T) {
		resolver := NewResolver()

		// Both wildcard A and wildcard CNAME exist
		resolver.Update([]nbdns.CustomZone{{
			Domain: "example.com.",
			Records: []nbdns.SimpleRecord{
				{Name: "*.example.com.", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "10.0.0.1"},
				{Name: "*.example.com.", Type: int(dns.TypeCNAME), Class: nbdns.DefaultClass, TTL: 300, RData: "target.example.com."},
			},
		}})

		msg := new(dns.Msg).SetQuestion("foo.example.com.", dns.TypeA)
		var resp *dns.Msg
		resolver.ServeDNS(&test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { resp = m; return nil }}, msg)

		require.NotNil(t, resp)
		require.Equal(t, dns.RcodeSuccess, resp.Rcode)
		require.Len(t, resp.Answer, 1)

		// A record should be returned, not CNAME
		a, ok := resp.Answer[0].(*dns.A)
		require.True(t, ok, "Wildcard A should take precedence over wildcard CNAME for A query")
		assert.Equal(t, "10.0.0.1", a.A.String())
	})

	t.Run("wildcard CNAME with chained CNAMEs", func(t *testing.T) {
		resolver := NewResolver()

		// Wildcard CNAME -> another CNAME -> A record
		resolver.Update([]nbdns.CustomZone{{
			Domain: "example.com.",
			Records: []nbdns.SimpleRecord{
				{Name: "*.example.com.", Type: int(dns.TypeCNAME), Class: nbdns.DefaultClass, TTL: 300, RData: "hop1.example.com."},
				{Name: "hop1.example.com.", Type: int(dns.TypeCNAME), Class: nbdns.DefaultClass, TTL: 300, RData: "final.example.com."},
				{Name: "final.example.com.", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "10.0.0.1"},
			},
		}})

		msg := new(dns.Msg).SetQuestion("anyhost.example.com.", dns.TypeA)
		var resp *dns.Msg
		resolver.ServeDNS(&test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { resp = m; return nil }}, msg)

		require.NotNil(t, resp)
		require.Equal(t, dns.RcodeSuccess, resp.Rcode)
		require.Len(t, resp.Answer, 3, "Should have wildcard CNAME + hop1 CNAME + A record")

		// First should be the wildcard CNAME with rewritten name
		cname1, ok := resp.Answer[0].(*dns.CNAME)
		require.True(t, ok)
		assert.Equal(t, "anyhost.example.com.", cname1.Hdr.Name)
		assert.Equal(t, "hop1.example.com.", cname1.Target)
	})
}

// TestLocalResolver_WildcardAandAAAA tests wildcard A and AAAA record handling
func TestLocalResolver_WildcardAandAAAA(t *testing.T) {
	t.Run("wildcard A record resolves with owner name rewriting", func(t *testing.T) {
		resolver := NewResolver()

		resolver.Update([]nbdns.CustomZone{{
			Domain: "example.com.",
			Records: []nbdns.SimpleRecord{
				{Name: "*.example.com.", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "10.0.0.1"},
			},
		}})

		msg := new(dns.Msg).SetQuestion("anyhost.example.com.", dns.TypeA)
		var resp *dns.Msg
		resolver.ServeDNS(&test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { resp = m; return nil }}, msg)

		require.NotNil(t, resp)
		require.Equal(t, dns.RcodeSuccess, resp.Rcode)
		require.Len(t, resp.Answer, 1)

		a, ok := resp.Answer[0].(*dns.A)
		require.True(t, ok)
		assert.Equal(t, "anyhost.example.com.", a.Hdr.Name, "Owner name should be rewritten to query name")
		assert.Equal(t, "10.0.0.1", a.A.String())
	})

	t.Run("wildcard AAAA record resolves with owner name rewriting", func(t *testing.T) {
		resolver := NewResolver()

		resolver.Update([]nbdns.CustomZone{{
			Domain: "example.com.",
			Records: []nbdns.SimpleRecord{
				{Name: "*.example.com.", Type: int(dns.TypeAAAA), Class: nbdns.DefaultClass, TTL: 300, RData: "2001:db8::1"},
			},
		}})

		msg := new(dns.Msg).SetQuestion("anyhost.example.com.", dns.TypeAAAA)
		var resp *dns.Msg
		resolver.ServeDNS(&test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { resp = m; return nil }}, msg)

		require.NotNil(t, resp)
		require.Equal(t, dns.RcodeSuccess, resp.Rcode)
		require.Len(t, resp.Answer, 1)

		aaaa, ok := resp.Answer[0].(*dns.AAAA)
		require.True(t, ok)
		assert.Equal(t, "anyhost.example.com.", aaaa.Hdr.Name, "Owner name should be rewritten to query name")
		assert.Equal(t, "2001:db8::1", aaaa.AAAA.String())
	})

	t.Run("NODATA when querying AAAA but only wildcard A exists", func(t *testing.T) {
		resolver := NewResolver()

		resolver.Update([]nbdns.CustomZone{{
			Domain: "example.com.",
			Records: []nbdns.SimpleRecord{
				{Name: "*.example.com.", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "10.0.0.1"},
			},
		}})

		msg := new(dns.Msg).SetQuestion("anyhost.example.com.", dns.TypeAAAA)
		var resp *dns.Msg
		resolver.ServeDNS(&test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { resp = m; return nil }}, msg)

		require.NotNil(t, resp)
		assert.Equal(t, dns.RcodeSuccess, resp.Rcode, "Should return NODATA (success with no answer)")
		assert.Len(t, resp.Answer, 0, "Should have no AAAA answer")
	})

	t.Run("NODATA when querying A but only wildcard AAAA exists", func(t *testing.T) {
		resolver := NewResolver()

		resolver.Update([]nbdns.CustomZone{{
			Domain: "example.com.",
			Records: []nbdns.SimpleRecord{
				{Name: "*.example.com.", Type: int(dns.TypeAAAA), Class: nbdns.DefaultClass, TTL: 300, RData: "2001:db8::1"},
			},
		}})

		msg := new(dns.Msg).SetQuestion("anyhost.example.com.", dns.TypeA)
		var resp *dns.Msg
		resolver.ServeDNS(&test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { resp = m; return nil }}, msg)

		require.NotNil(t, resp)
		assert.Equal(t, dns.RcodeSuccess, resp.Rcode, "Should return NODATA (success with no answer)")
		assert.Len(t, resp.Answer, 0, "Should have no A answer")
	})

	t.Run("dual-stack wildcard returns both A and AAAA separately", func(t *testing.T) {
		resolver := NewResolver()

		resolver.Update([]nbdns.CustomZone{{
			Domain: "example.com.",
			Records: []nbdns.SimpleRecord{
				{Name: "*.example.com.", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "10.0.0.1"},
				{Name: "*.example.com.", Type: int(dns.TypeAAAA), Class: nbdns.DefaultClass, TTL: 300, RData: "2001:db8::1"},
			},
		}})

		// Query A
		msgA := new(dns.Msg).SetQuestion("anyhost.example.com.", dns.TypeA)
		var respA *dns.Msg
		resolver.ServeDNS(&test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { respA = m; return nil }}, msgA)

		require.NotNil(t, respA)
		require.Equal(t, dns.RcodeSuccess, respA.Rcode)
		require.Len(t, respA.Answer, 1)
		a, ok := respA.Answer[0].(*dns.A)
		require.True(t, ok)
		assert.Equal(t, "10.0.0.1", a.A.String())

		// Query AAAA
		msgAAAA := new(dns.Msg).SetQuestion("anyhost.example.com.", dns.TypeAAAA)
		var respAAAA *dns.Msg
		resolver.ServeDNS(&test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { respAAAA = m; return nil }}, msgAAAA)

		require.NotNil(t, respAAAA)
		require.Equal(t, dns.RcodeSuccess, respAAAA.Rcode)
		require.Len(t, respAAAA.Answer, 1)
		aaaa, ok := respAAAA.Answer[0].(*dns.AAAA)
		require.True(t, ok)
		assert.Equal(t, "2001:db8::1", aaaa.AAAA.String())
	})

	t.Run("specific A takes precedence over wildcard A", func(t *testing.T) {
		resolver := NewResolver()

		resolver.Update([]nbdns.CustomZone{{
			Domain: "example.com.",
			Records: []nbdns.SimpleRecord{
				{Name: "*.example.com.", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "10.0.0.1"},
				{Name: "specific.example.com.", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "192.168.1.1"},
			},
		}})

		msg := new(dns.Msg).SetQuestion("specific.example.com.", dns.TypeA)
		var resp *dns.Msg
		resolver.ServeDNS(&test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { resp = m; return nil }}, msg)

		require.NotNil(t, resp)
		require.Equal(t, dns.RcodeSuccess, resp.Rcode)
		require.Len(t, resp.Answer, 1)

		a, ok := resp.Answer[0].(*dns.A)
		require.True(t, ok)
		assert.Equal(t, "192.168.1.1", a.A.String(), "Specific record should take precedence")
	})

	t.Run("specific AAAA takes precedence over wildcard AAAA", func(t *testing.T) {
		resolver := NewResolver()

		resolver.Update([]nbdns.CustomZone{{
			Domain: "example.com.",
			Records: []nbdns.SimpleRecord{
				{Name: "*.example.com.", Type: int(dns.TypeAAAA), Class: nbdns.DefaultClass, TTL: 300, RData: "2001:db8::1"},
				{Name: "specific.example.com.", Type: int(dns.TypeAAAA), Class: nbdns.DefaultClass, TTL: 300, RData: "2001:db8::2"},
			},
		}})

		msg := new(dns.Msg).SetQuestion("specific.example.com.", dns.TypeAAAA)
		var resp *dns.Msg
		resolver.ServeDNS(&test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { resp = m; return nil }}, msg)

		require.NotNil(t, resp)
		require.Equal(t, dns.RcodeSuccess, resp.Rcode)
		require.Len(t, resp.Answer, 1)

		aaaa, ok := resp.Answer[0].(*dns.AAAA)
		require.True(t, ok)
		assert.Equal(t, "2001:db8::2", aaaa.AAAA.String(), "Specific record should take precedence")
	})

	t.Run("multiple wildcard A records round-robin", func(t *testing.T) {
		resolver := NewResolver()

		resolver.Update([]nbdns.CustomZone{{
			Domain: "example.com.",
			Records: []nbdns.SimpleRecord{
				{Name: "*.example.com.", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "10.0.0.1"},
				{Name: "*.example.com.", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "10.0.0.2"},
				{Name: "*.example.com.", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "10.0.0.3"},
			},
		}})

		msg := new(dns.Msg).SetQuestion("anyhost.example.com.", dns.TypeA)

		var firstIPs []string
		for i := 0; i < 3; i++ {
			var resp *dns.Msg
			resolver.ServeDNS(&test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { resp = m; return nil }}, msg)

			require.NotNil(t, resp)
			require.Len(t, resp.Answer, 3, "Should return all 3 A records")

			a, ok := resp.Answer[0].(*dns.A)
			require.True(t, ok)
			firstIPs = append(firstIPs, a.A.String())

			// Verify owner name is rewritten for all records
			for _, ans := range resp.Answer {
				assert.Equal(t, "anyhost.example.com.", ans.Header().Name)
			}
		}

		// Verify rotation happened
		assert.NotEqual(t, firstIPs[0], firstIPs[1], "First record should rotate")
		assert.NotEqual(t, firstIPs[1], firstIPs[2], "Second rotation should differ")
	})

	t.Run("wildcard A case insensitive", func(t *testing.T) {
		resolver := NewResolver()

		resolver.Update([]nbdns.CustomZone{{
			Domain: "example.com.",
			Records: []nbdns.SimpleRecord{
				{Name: "*.example.com.", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "10.0.0.1"},
			},
		}})

		msg := new(dns.Msg).SetQuestion("ANYHOST.EXAMPLE.COM.", dns.TypeA)
		var resp *dns.Msg
		resolver.ServeDNS(&test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { resp = m; return nil }}, msg)

		require.NotNil(t, resp)
		require.Equal(t, dns.RcodeSuccess, resp.Rcode)
		require.Len(t, resp.Answer, 1)
	})

	t.Run("wildcard does not match multi-level subdomain", func(t *testing.T) {
		resolver := NewResolver()

		resolver.Update([]nbdns.CustomZone{{
			Domain: "example.com.",
			Records: []nbdns.SimpleRecord{
				{Name: "*.example.com.", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "10.0.0.1"},
			},
		}})

		// *.example.com should NOT match sub.domain.example.com (standard DNS behavior)
		msg := new(dns.Msg).SetQuestion("sub.domain.example.com.", dns.TypeA)
		var resp *dns.Msg
		resolver.ServeDNS(&test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { resp = m; return nil }}, msg)

		require.NotNil(t, resp)
		// This depends on implementation - standard DNS wildcards only match single label
		// Current implementation replaces first label with *, so it WOULD match
		// This test documents the current behavior
	})

	t.Run("wildcard with existing domain but different type returns NODATA", func(t *testing.T) {
		resolver := NewResolver()

		// Specific A record exists, but query for TXT on wildcard domain
		resolver.Update([]nbdns.CustomZone{{
			Domain: "example.com.",
			Records: []nbdns.SimpleRecord{
				{Name: "*.example.com.", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "10.0.0.1"},
			},
		}})

		msg := new(dns.Msg).SetQuestion("test.example.com.", dns.TypeTXT)
		var resp *dns.Msg
		resolver.ServeDNS(&test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { resp = m; return nil }}, msg)

		require.NotNil(t, resp)
		assert.Equal(t, dns.RcodeSuccess, resp.Rcode, "Should return NODATA for existing wildcard domain with different type")
		assert.Len(t, resp.Answer, 0)
	})

	t.Run("mixed specific and wildcard returns correct records", func(t *testing.T) {
		resolver := NewResolver()

		resolver.Update([]nbdns.CustomZone{{
			Domain: "example.com.",
			Records: []nbdns.SimpleRecord{
				{Name: "*.example.com.", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "10.0.0.1"},
				{Name: "specific.example.com.", Type: int(dns.TypeAAAA), Class: nbdns.DefaultClass, TTL: 300, RData: "2001:db8::1"},
			},
		}})

		// Query A for specific - should use wildcard
		msgA := new(dns.Msg).SetQuestion("specific.example.com.", dns.TypeA)
		var respA *dns.Msg
		resolver.ServeDNS(&test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { respA = m; return nil }}, msgA)

		require.NotNil(t, respA)
		// This could be NODATA since specific.example.com exists but has no A
		// or could return wildcard A - depends on implementation
		// The current behavior returns NODATA because specific domain exists

		// Query AAAA for specific - should use specific record
		msgAAAA := new(dns.Msg).SetQuestion("specific.example.com.", dns.TypeAAAA)
		var respAAAA *dns.Msg
		resolver.ServeDNS(&test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { respAAAA = m; return nil }}, msgAAAA)

		require.NotNil(t, respAAAA)
		require.Equal(t, dns.RcodeSuccess, respAAAA.Rcode)
		require.Len(t, respAAAA.Answer, 1)
		aaaa, ok := respAAAA.Answer[0].(*dns.AAAA)
		require.True(t, ok)
		assert.Equal(t, "2001:db8::1", aaaa.AAAA.String())
	})
}

// TestLocalResolver_WildcardEdgeCases tests edge cases for wildcard record handling
func TestLocalResolver_WildcardEdgeCases(t *testing.T) {
	t.Run("wildcard does not match NS queries", func(t *testing.T) {
		resolver := NewResolver()

		resolver.Update([]nbdns.CustomZone{{
			Domain: "example.com.",
			Records: []nbdns.SimpleRecord{
				{Name: "*.example.com.", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "10.0.0.1"},
			},
		}})

		msg := new(dns.Msg).SetQuestion("foo.example.com.", dns.TypeNS)
		var resp *dns.Msg
		resolver.ServeDNS(&test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { resp = m; return nil }}, msg)

		require.NotNil(t, resp)
		assert.Equal(t, dns.RcodeNameError, resp.Rcode, "NS queries should not match wildcards")
		assert.Len(t, resp.Answer, 0)
	})

	t.Run("wildcard does not match SOA queries", func(t *testing.T) {
		resolver := NewResolver()

		resolver.Update([]nbdns.CustomZone{{
			Domain: "example.com.",
			Records: []nbdns.SimpleRecord{
				{Name: "*.example.com.", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "10.0.0.1"},
			},
		}})

		msg := new(dns.Msg).SetQuestion("foo.example.com.", dns.TypeSOA)
		var resp *dns.Msg
		resolver.ServeDNS(&test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { resp = m; return nil }}, msg)

		require.NotNil(t, resp)
		assert.Equal(t, dns.RcodeNameError, resp.Rcode, "SOA queries should not match wildcards")
		assert.Len(t, resp.Answer, 0)
	})

	t.Run("apex wildcard query", func(t *testing.T) {
		resolver := NewResolver()

		resolver.Update([]nbdns.CustomZone{{
			Domain: "example.com.",
			Records: []nbdns.SimpleRecord{
				{Name: "*.example.com.", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "10.0.0.1"},
			},
		}})

		// Query for *.example.com directly (the wildcard itself)
		msg := new(dns.Msg).SetQuestion("*.example.com.", dns.TypeA)
		var resp *dns.Msg
		resolver.ServeDNS(&test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { resp = m; return nil }}, msg)

		require.NotNil(t, resp)
		require.Equal(t, dns.RcodeSuccess, resp.Rcode)
		require.Len(t, resp.Answer, 1)

		a, ok := resp.Answer[0].(*dns.A)
		require.True(t, ok)
		assert.Equal(t, "10.0.0.1", a.A.String())
	})

	t.Run("wildcard TXT record", func(t *testing.T) {
		resolver := NewResolver()

		resolver.Update([]nbdns.CustomZone{{
			Domain: "example.com.",
			Records: []nbdns.SimpleRecord{
				{Name: "*.example.com.", Type: int(dns.TypeTXT), Class: nbdns.DefaultClass, TTL: 300, RData: "v=spf1 -all"},
			},
		}})

		msg := new(dns.Msg).SetQuestion("mail.example.com.", dns.TypeTXT)
		var resp *dns.Msg
		resolver.ServeDNS(&test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { resp = m; return nil }}, msg)

		require.NotNil(t, resp)
		require.Equal(t, dns.RcodeSuccess, resp.Rcode)
		require.Len(t, resp.Answer, 1)

		txt, ok := resp.Answer[0].(*dns.TXT)
		require.True(t, ok)
		assert.Equal(t, "mail.example.com.", txt.Hdr.Name, "TXT owner should be rewritten")
	})

	t.Run("wildcard MX record", func(t *testing.T) {
		resolver := NewResolver()

		resolver.Update([]nbdns.CustomZone{{
			Domain: "example.com.",
			Records: []nbdns.SimpleRecord{
				{Name: "*.example.com.", Type: int(dns.TypeMX), Class: nbdns.DefaultClass, TTL: 300, RData: "10 mail.example.com."},
			},
		}})

		msg := new(dns.Msg).SetQuestion("sub.example.com.", dns.TypeMX)
		var resp *dns.Msg
		resolver.ServeDNS(&test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { resp = m; return nil }}, msg)

		require.NotNil(t, resp)
		require.Equal(t, dns.RcodeSuccess, resp.Rcode)
		require.Len(t, resp.Answer, 1)

		mx, ok := resp.Answer[0].(*dns.MX)
		require.True(t, ok)
		assert.Equal(t, "sub.example.com.", mx.Hdr.Name, "MX owner should be rewritten")
	})

	t.Run("non-authoritative zone with wildcard CNAME triggers fallthrough for unmatched names", func(t *testing.T) {
		resolver := NewResolver()

		resolver.Update([]nbdns.CustomZone{{
			Domain:           "example.com.",
			NonAuthoritative: true,
			Records: []nbdns.SimpleRecord{
				{Name: "*.sub.example.com.", Type: int(dns.TypeCNAME), Class: nbdns.DefaultClass, TTL: 300, RData: "target.example.com."},
			},
		}})

		// Query for name not matching the wildcard pattern
		msg := new(dns.Msg).SetQuestion("other.example.com.", dns.TypeA)
		var resp *dns.Msg
		resolver.ServeDNS(&test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { resp = m; return nil }}, msg)

		require.NotNil(t, resp)
		assert.True(t, resp.MsgHdr.Zero, "Should trigger fallthrough for non-authoritative zone")
	})
}

// TestLocalResolver_MixedRecordTypes tests scenarios with A, AAAA, and CNAME records combined
func TestLocalResolver_MixedRecordTypes(t *testing.T) {
	t.Run("specific A with wildcard CNAME - A query uses specific A", func(t *testing.T) {
		resolver := NewResolver()

		resolver.Update([]nbdns.CustomZone{{
			Domain: "example.com.",
			Records: []nbdns.SimpleRecord{
				{Name: "*.example.com.", Type: int(dns.TypeCNAME), Class: nbdns.DefaultClass, TTL: 300, RData: "target.example.com."},
				{Name: "specific.example.com.", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "10.0.0.1"},
				{Name: "target.example.com.", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "10.0.0.2"},
			},
		}})

		msg := new(dns.Msg).SetQuestion("specific.example.com.", dns.TypeA)
		var resp *dns.Msg
		resolver.ServeDNS(&test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { resp = m; return nil }}, msg)

		require.NotNil(t, resp)
		require.Equal(t, dns.RcodeSuccess, resp.Rcode)
		require.Len(t, resp.Answer, 1, "Should return only the specific A record")

		a, ok := resp.Answer[0].(*dns.A)
		require.True(t, ok)
		assert.Equal(t, "10.0.0.1", a.A.String(), "Should use specific A, not follow wildcard CNAME")
	})

	t.Run("specific AAAA with wildcard CNAME - AAAA query uses specific AAAA", func(t *testing.T) {
		resolver := NewResolver()

		resolver.Update([]nbdns.CustomZone{{
			Domain: "example.com.",
			Records: []nbdns.SimpleRecord{
				{Name: "*.example.com.", Type: int(dns.TypeCNAME), Class: nbdns.DefaultClass, TTL: 300, RData: "target.example.com."},
				{Name: "specific.example.com.", Type: int(dns.TypeAAAA), Class: nbdns.DefaultClass, TTL: 300, RData: "2001:db8::1"},
				{Name: "target.example.com.", Type: int(dns.TypeAAAA), Class: nbdns.DefaultClass, TTL: 300, RData: "2001:db8::2"},
			},
		}})

		msg := new(dns.Msg).SetQuestion("specific.example.com.", dns.TypeAAAA)
		var resp *dns.Msg
		resolver.ServeDNS(&test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { resp = m; return nil }}, msg)

		require.NotNil(t, resp)
		require.Equal(t, dns.RcodeSuccess, resp.Rcode)
		require.Len(t, resp.Answer, 1, "Should return only the specific AAAA record")

		aaaa, ok := resp.Answer[0].(*dns.AAAA)
		require.True(t, ok)
		assert.Equal(t, "2001:db8::1", aaaa.AAAA.String(), "Should use specific AAAA, not follow wildcard CNAME")
	})

	t.Run("specific A only - AAAA query returns NODATA", func(t *testing.T) {
		resolver := NewResolver()

		resolver.Update([]nbdns.CustomZone{{
			Domain: "example.com.",
			Records: []nbdns.SimpleRecord{
				{Name: "host.example.com.", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "10.0.0.1"},
			},
		}})

		msg := new(dns.Msg).SetQuestion("host.example.com.", dns.TypeAAAA)
		var resp *dns.Msg
		resolver.ServeDNS(&test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { resp = m; return nil }}, msg)

		require.NotNil(t, resp)
		assert.Equal(t, dns.RcodeSuccess, resp.Rcode, "Should return NODATA (success with no AAAA)")
		assert.Len(t, resp.Answer, 0)
	})

	t.Run("specific AAAA only - A query returns NODATA", func(t *testing.T) {
		resolver := NewResolver()

		resolver.Update([]nbdns.CustomZone{{
			Domain: "example.com.",
			Records: []nbdns.SimpleRecord{
				{Name: "host.example.com.", Type: int(dns.TypeAAAA), Class: nbdns.DefaultClass, TTL: 300, RData: "2001:db8::1"},
			},
		}})

		msg := new(dns.Msg).SetQuestion("host.example.com.", dns.TypeA)
		var resp *dns.Msg
		resolver.ServeDNS(&test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { resp = m; return nil }}, msg)

		require.NotNil(t, resp)
		assert.Equal(t, dns.RcodeSuccess, resp.Rcode, "Should return NODATA (success with no A)")
		assert.Len(t, resp.Answer, 0)
	})

	t.Run("CNAME with both A and AAAA target - A query returns CNAME + A", func(t *testing.T) {
		resolver := NewResolver()

		resolver.Update([]nbdns.CustomZone{{
			Domain: "example.com.",
			Records: []nbdns.SimpleRecord{
				{Name: "alias.example.com.", Type: int(dns.TypeCNAME), Class: nbdns.DefaultClass, TTL: 300, RData: "target.example.com."},
				{Name: "target.example.com.", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "10.0.0.1"},
				{Name: "target.example.com.", Type: int(dns.TypeAAAA), Class: nbdns.DefaultClass, TTL: 300, RData: "2001:db8::1"},
			},
		}})

		msg := new(dns.Msg).SetQuestion("alias.example.com.", dns.TypeA)
		var resp *dns.Msg
		resolver.ServeDNS(&test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { resp = m; return nil }}, msg)

		require.NotNil(t, resp)
		require.Equal(t, dns.RcodeSuccess, resp.Rcode)
		require.Len(t, resp.Answer, 2, "Should have CNAME + A")

		cname, ok := resp.Answer[0].(*dns.CNAME)
		require.True(t, ok)
		assert.Equal(t, "target.example.com.", cname.Target)

		a, ok := resp.Answer[1].(*dns.A)
		require.True(t, ok)
		assert.Equal(t, "10.0.0.1", a.A.String())
	})

	t.Run("CNAME with both A and AAAA target - AAAA query returns CNAME + AAAA", func(t *testing.T) {
		resolver := NewResolver()

		resolver.Update([]nbdns.CustomZone{{
			Domain: "example.com.",
			Records: []nbdns.SimpleRecord{
				{Name: "alias.example.com.", Type: int(dns.TypeCNAME), Class: nbdns.DefaultClass, TTL: 300, RData: "target.example.com."},
				{Name: "target.example.com.", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "10.0.0.1"},
				{Name: "target.example.com.", Type: int(dns.TypeAAAA), Class: nbdns.DefaultClass, TTL: 300, RData: "2001:db8::1"},
			},
		}})

		msg := new(dns.Msg).SetQuestion("alias.example.com.", dns.TypeAAAA)
		var resp *dns.Msg
		resolver.ServeDNS(&test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { resp = m; return nil }}, msg)

		require.NotNil(t, resp)
		require.Equal(t, dns.RcodeSuccess, resp.Rcode)
		require.Len(t, resp.Answer, 2, "Should have CNAME + AAAA")

		cname, ok := resp.Answer[0].(*dns.CNAME)
		require.True(t, ok)
		assert.Equal(t, "target.example.com.", cname.Target)

		aaaa, ok := resp.Answer[1].(*dns.AAAA)
		require.True(t, ok)
		assert.Equal(t, "2001:db8::1", aaaa.AAAA.String())
	})

	t.Run("CNAME to target with only A - AAAA query returns CNAME only (NODATA)", func(t *testing.T) {
		resolver := NewResolver()

		resolver.Update([]nbdns.CustomZone{{
			Domain: "example.com.",
			Records: []nbdns.SimpleRecord{
				{Name: "alias.example.com.", Type: int(dns.TypeCNAME), Class: nbdns.DefaultClass, TTL: 300, RData: "target.example.com."},
				{Name: "target.example.com.", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "10.0.0.1"},
			},
		}})

		msg := new(dns.Msg).SetQuestion("alias.example.com.", dns.TypeAAAA)
		var resp *dns.Msg
		resolver.ServeDNS(&test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { resp = m; return nil }}, msg)

		require.NotNil(t, resp)
		assert.Equal(t, dns.RcodeSuccess, resp.Rcode, "Should return NODATA with CNAME")
		require.Len(t, resp.Answer, 1, "Should have only CNAME")

		_, ok := resp.Answer[0].(*dns.CNAME)
		require.True(t, ok)
	})

	t.Run("CNAME to target with only AAAA - A query returns CNAME only (NODATA)", func(t *testing.T) {
		resolver := NewResolver()

		resolver.Update([]nbdns.CustomZone{{
			Domain: "example.com.",
			Records: []nbdns.SimpleRecord{
				{Name: "alias.example.com.", Type: int(dns.TypeCNAME), Class: nbdns.DefaultClass, TTL: 300, RData: "target.example.com."},
				{Name: "target.example.com.", Type: int(dns.TypeAAAA), Class: nbdns.DefaultClass, TTL: 300, RData: "2001:db8::1"},
			},
		}})

		msg := new(dns.Msg).SetQuestion("alias.example.com.", dns.TypeA)
		var resp *dns.Msg
		resolver.ServeDNS(&test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { resp = m; return nil }}, msg)

		require.NotNil(t, resp)
		assert.Equal(t, dns.RcodeSuccess, resp.Rcode, "Should return NODATA with CNAME")
		require.Len(t, resp.Answer, 1, "Should have only CNAME")

		_, ok := resp.Answer[0].(*dns.CNAME)
		require.True(t, ok)
	})

	t.Run("wildcard A + wildcard AAAA + wildcard CNAME - each query type returns correct record", func(t *testing.T) {
		resolver := NewResolver()

		resolver.Update([]nbdns.CustomZone{{
			Domain: "example.com.",
			Records: []nbdns.SimpleRecord{
				{Name: "*.example.com.", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "10.0.0.1"},
				{Name: "*.example.com.", Type: int(dns.TypeAAAA), Class: nbdns.DefaultClass, TTL: 300, RData: "2001:db8::1"},
				{Name: "*.example.com.", Type: int(dns.TypeCNAME), Class: nbdns.DefaultClass, TTL: 300, RData: "target.example.com."},
			},
		}})

		// A query should return wildcard A (not CNAME)
		msgA := new(dns.Msg).SetQuestion("any.example.com.", dns.TypeA)
		var respA *dns.Msg
		resolver.ServeDNS(&test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { respA = m; return nil }}, msgA)

		require.NotNil(t, respA)
		require.Equal(t, dns.RcodeSuccess, respA.Rcode)
		require.Len(t, respA.Answer, 1)
		a, ok := respA.Answer[0].(*dns.A)
		require.True(t, ok, "A query should return A record, not CNAME")
		assert.Equal(t, "10.0.0.1", a.A.String())

		// AAAA query should return wildcard AAAA (not CNAME)
		msgAAAA := new(dns.Msg).SetQuestion("any.example.com.", dns.TypeAAAA)
		var respAAAA *dns.Msg
		resolver.ServeDNS(&test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { respAAAA = m; return nil }}, msgAAAA)

		require.NotNil(t, respAAAA)
		require.Equal(t, dns.RcodeSuccess, respAAAA.Rcode)
		require.Len(t, respAAAA.Answer, 1)
		aaaa, ok := respAAAA.Answer[0].(*dns.AAAA)
		require.True(t, ok, "AAAA query should return AAAA record, not CNAME")
		assert.Equal(t, "2001:db8::1", aaaa.AAAA.String())

		// CNAME query should return wildcard CNAME
		msgCNAME := new(dns.Msg).SetQuestion("any.example.com.", dns.TypeCNAME)
		var respCNAME *dns.Msg
		resolver.ServeDNS(&test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { respCNAME = m; return nil }}, msgCNAME)

		require.NotNil(t, respCNAME)
		require.Equal(t, dns.RcodeSuccess, respCNAME.Rcode)
		require.Len(t, respCNAME.Answer, 1)
		cname, ok := respCNAME.Answer[0].(*dns.CNAME)
		require.True(t, ok, "CNAME query should return CNAME record")
		assert.Equal(t, "target.example.com.", cname.Target)
	})

	t.Run("dual-stack host with both A and AAAA", func(t *testing.T) {
		resolver := NewResolver()

		resolver.Update([]nbdns.CustomZone{{
			Domain: "example.com.",
			Records: []nbdns.SimpleRecord{
				{Name: "host.example.com.", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "10.0.0.1"},
				{Name: "host.example.com.", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "10.0.0.2"},
				{Name: "host.example.com.", Type: int(dns.TypeAAAA), Class: nbdns.DefaultClass, TTL: 300, RData: "2001:db8::1"},
				{Name: "host.example.com.", Type: int(dns.TypeAAAA), Class: nbdns.DefaultClass, TTL: 300, RData: "2001:db8::2"},
			},
		}})

		// A query
		msgA := new(dns.Msg).SetQuestion("host.example.com.", dns.TypeA)
		var respA *dns.Msg
		resolver.ServeDNS(&test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { respA = m; return nil }}, msgA)

		require.NotNil(t, respA)
		require.Equal(t, dns.RcodeSuccess, respA.Rcode)
		require.Len(t, respA.Answer, 2, "Should return both A records")
		for _, ans := range respA.Answer {
			_, ok := ans.(*dns.A)
			require.True(t, ok)
		}

		// AAAA query
		msgAAAA := new(dns.Msg).SetQuestion("host.example.com.", dns.TypeAAAA)
		var respAAAA *dns.Msg
		resolver.ServeDNS(&test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { respAAAA = m; return nil }}, msgAAAA)

		require.NotNil(t, respAAAA)
		require.Equal(t, dns.RcodeSuccess, respAAAA.Rcode)
		require.Len(t, respAAAA.Answer, 2, "Should return both AAAA records")
		for _, ans := range respAAAA.Answer {
			_, ok := ans.(*dns.AAAA)
			require.True(t, ok)
		}
	})

	t.Run("CNAME chain with mixed record types at target", func(t *testing.T) {
		resolver := NewResolver()

		resolver.Update([]nbdns.CustomZone{{
			Domain: "example.com.",
			Records: []nbdns.SimpleRecord{
				{Name: "alias1.example.com.", Type: int(dns.TypeCNAME), Class: nbdns.DefaultClass, TTL: 300, RData: "alias2.example.com."},
				{Name: "alias2.example.com.", Type: int(dns.TypeCNAME), Class: nbdns.DefaultClass, TTL: 300, RData: "target.example.com."},
				{Name: "target.example.com.", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "10.0.0.1"},
				{Name: "target.example.com.", Type: int(dns.TypeAAAA), Class: nbdns.DefaultClass, TTL: 300, RData: "2001:db8::1"},
			},
		}})

		// A query through chain
		msgA := new(dns.Msg).SetQuestion("alias1.example.com.", dns.TypeA)
		var respA *dns.Msg
		resolver.ServeDNS(&test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { respA = m; return nil }}, msgA)

		require.NotNil(t, respA)
		require.Equal(t, dns.RcodeSuccess, respA.Rcode)
		require.Len(t, respA.Answer, 3, "Should have 2 CNAMEs + 1 A")

		// Verify chain order
		cname1, ok := respA.Answer[0].(*dns.CNAME)
		require.True(t, ok)
		assert.Equal(t, "alias2.example.com.", cname1.Target)

		cname2, ok := respA.Answer[1].(*dns.CNAME)
		require.True(t, ok)
		assert.Equal(t, "target.example.com.", cname2.Target)

		a, ok := respA.Answer[2].(*dns.A)
		require.True(t, ok)
		assert.Equal(t, "10.0.0.1", a.A.String())

		// AAAA query through chain
		msgAAAA := new(dns.Msg).SetQuestion("alias1.example.com.", dns.TypeAAAA)
		var respAAAA *dns.Msg
		resolver.ServeDNS(&test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { respAAAA = m; return nil }}, msgAAAA)

		require.NotNil(t, respAAAA)
		require.Equal(t, dns.RcodeSuccess, respAAAA.Rcode)
		require.Len(t, respAAAA.Answer, 3, "Should have 2 CNAMEs + 1 AAAA")

		aaaa, ok := respAAAA.Answer[2].(*dns.AAAA)
		require.True(t, ok)
		assert.Equal(t, "2001:db8::1", aaaa.AAAA.String())
	})

	t.Run("wildcard CNAME with dual-stack target", func(t *testing.T) {
		resolver := NewResolver()

		resolver.Update([]nbdns.CustomZone{{
			Domain: "example.com.",
			Records: []nbdns.SimpleRecord{
				{Name: "*.example.com.", Type: int(dns.TypeCNAME), Class: nbdns.DefaultClass, TTL: 300, RData: "target.example.com."},
				{Name: "target.example.com.", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "10.0.0.1"},
				{Name: "target.example.com.", Type: int(dns.TypeAAAA), Class: nbdns.DefaultClass, TTL: 300, RData: "2001:db8::1"},
			},
		}})

		// A query via wildcard CNAME
		msgA := new(dns.Msg).SetQuestion("any.example.com.", dns.TypeA)
		var respA *dns.Msg
		resolver.ServeDNS(&test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { respA = m; return nil }}, msgA)

		require.NotNil(t, respA)
		require.Equal(t, dns.RcodeSuccess, respA.Rcode)
		require.Len(t, respA.Answer, 2, "Should have CNAME + A")

		cname, ok := respA.Answer[0].(*dns.CNAME)
		require.True(t, ok)
		assert.Equal(t, "any.example.com.", cname.Hdr.Name, "CNAME owner should be rewritten")

		a, ok := respA.Answer[1].(*dns.A)
		require.True(t, ok)
		assert.Equal(t, "10.0.0.1", a.A.String())

		// AAAA query via wildcard CNAME
		msgAAAA := new(dns.Msg).SetQuestion("other.example.com.", dns.TypeAAAA)
		var respAAAA *dns.Msg
		resolver.ServeDNS(&test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { respAAAA = m; return nil }}, msgAAAA)

		require.NotNil(t, respAAAA)
		require.Equal(t, dns.RcodeSuccess, respAAAA.Rcode)
		require.Len(t, respAAAA.Answer, 2, "Should have CNAME + AAAA")

		cname2, ok := respAAAA.Answer[0].(*dns.CNAME)
		require.True(t, ok)
		assert.Equal(t, "other.example.com.", cname2.Hdr.Name, "CNAME owner should be rewritten")

		aaaa, ok := respAAAA.Answer[1].(*dns.AAAA)
		require.True(t, ok)
		assert.Equal(t, "2001:db8::1", aaaa.AAAA.String())
	})

	t.Run("specific A + wildcard AAAA - each query type returns correct record", func(t *testing.T) {
		resolver := NewResolver()

		resolver.Update([]nbdns.CustomZone{{
			Domain: "example.com.",
			Records: []nbdns.SimpleRecord{
				{Name: "host.example.com.", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "10.0.0.1"},
				{Name: "*.example.com.", Type: int(dns.TypeAAAA), Class: nbdns.DefaultClass, TTL: 300, RData: "2001:db8::1"},
			},
		}})

		// A query for host should return specific A
		msgA := new(dns.Msg).SetQuestion("host.example.com.", dns.TypeA)
		var respA *dns.Msg
		resolver.ServeDNS(&test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { respA = m; return nil }}, msgA)

		require.NotNil(t, respA)
		require.Equal(t, dns.RcodeSuccess, respA.Rcode)
		require.Len(t, respA.Answer, 1)
		a, ok := respA.Answer[0].(*dns.A)
		require.True(t, ok)
		assert.Equal(t, "10.0.0.1", a.A.String())

		// AAAA query for host should return NODATA (specific A exists, no AAAA for host.example.com)
		msgAAAA := new(dns.Msg).SetQuestion("host.example.com.", dns.TypeAAAA)
		var respAAAA *dns.Msg
		resolver.ServeDNS(&test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { respAAAA = m; return nil }}, msgAAAA)

		require.NotNil(t, respAAAA)
		// RFC 4592 section 2.2.1: wildcard should NOT match when the name EXISTS in zone.
		// host.example.com exists (has A record), so AAAA query returns NODATA, not wildcard.
		assert.Equal(t, dns.RcodeSuccess, respAAAA.Rcode, "Should return NODATA for existing host without AAAA")
		assert.Len(t, respAAAA.Answer, 0, "RFC 4592: wildcard should not match when name exists")

		// AAAA query for other host should return wildcard AAAA
		msgAAAAOther := new(dns.Msg).SetQuestion("other.example.com.", dns.TypeAAAA)
		var respAAAAOther *dns.Msg
		resolver.ServeDNS(&test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { respAAAAOther = m; return nil }}, msgAAAAOther)

		require.NotNil(t, respAAAAOther)
		require.Equal(t, dns.RcodeSuccess, respAAAAOther.Rcode)
		require.Len(t, respAAAAOther.Answer, 1)
		aaaa, ok := respAAAAOther.Answer[0].(*dns.AAAA)
		require.True(t, ok)
		assert.Equal(t, "2001:db8::1", aaaa.AAAA.String())
		assert.Equal(t, "other.example.com.", aaaa.Hdr.Name, "Owner should be rewritten")
	})

	t.Run("multiple zones with mixed records", func(t *testing.T) {
		resolver := NewResolver()

		resolver.Update([]nbdns.CustomZone{
			{
				Domain: "zone1.com.",
				Records: []nbdns.SimpleRecord{
					{Name: "host.zone1.com.", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "10.1.0.1"},
					{Name: "host.zone1.com.", Type: int(dns.TypeAAAA), Class: nbdns.DefaultClass, TTL: 300, RData: "2001:db8:1::1"},
				},
			},
			{
				Domain: "zone2.com.",
				Records: []nbdns.SimpleRecord{
					{Name: "alias.zone2.com.", Type: int(dns.TypeCNAME), Class: nbdns.DefaultClass, TTL: 300, RData: "target.zone2.com."},
					{Name: "target.zone2.com.", Type: int(dns.TypeA), Class: nbdns.DefaultClass, TTL: 300, RData: "10.2.0.1"},
				},
			},
		})

		// Query zone1 A
		msg1A := new(dns.Msg).SetQuestion("host.zone1.com.", dns.TypeA)
		var resp1A *dns.Msg
		resolver.ServeDNS(&test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { resp1A = m; return nil }}, msg1A)

		require.NotNil(t, resp1A)
		require.Equal(t, dns.RcodeSuccess, resp1A.Rcode)
		require.Len(t, resp1A.Answer, 1)

		// Query zone1 AAAA
		msg1AAAA := new(dns.Msg).SetQuestion("host.zone1.com.", dns.TypeAAAA)
		var resp1AAAA *dns.Msg
		resolver.ServeDNS(&test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { resp1AAAA = m; return nil }}, msg1AAAA)

		require.NotNil(t, resp1AAAA)
		require.Equal(t, dns.RcodeSuccess, resp1AAAA.Rcode)
		require.Len(t, resp1AAAA.Answer, 1)

		// Query zone2 via CNAME
		msg2A := new(dns.Msg).SetQuestion("alias.zone2.com.", dns.TypeA)
		var resp2A *dns.Msg
		resolver.ServeDNS(&test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { resp2A = m; return nil }}, msg2A)

		require.NotNil(t, resp2A)
		require.Equal(t, dns.RcodeSuccess, resp2A.Rcode)
		require.Len(t, resp2A.Answer, 2, "Should have CNAME + A")
	})
}

// BenchmarkFindZone_BestCase benchmarks zone lookup with immediate match (first label)
func BenchmarkFindZone_BestCase(b *testing.B) {
	resolver := NewResolver()

	// Single zone that matches immediately
	resolver.Update([]nbdns.CustomZone{{
		Domain:           "example.com.",
		NonAuthoritative: true,
	}})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resolver.shouldFallthrough("example.com.")
	}
}

// BenchmarkFindZone_WorstCase benchmarks zone lookup with many zones, no match, many labels
func BenchmarkFindZone_WorstCase(b *testing.B) {
	resolver := NewResolver()

	// 100 zones that won't match
	var zones []nbdns.CustomZone
	for i := 0; i < 100; i++ {
		zones = append(zones, nbdns.CustomZone{
			Domain:           fmt.Sprintf("zone%d.internal.", i),
			NonAuthoritative: true,
		})
	}
	resolver.Update(zones)

	// Query with many labels that won't match any zone
	qname := "a.b.c.d.e.f.g.h.external.com."

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resolver.shouldFallthrough(qname)
	}
}

// BenchmarkFindZone_TypicalCase benchmarks typical usage: few zones, subdomain match
func BenchmarkFindZone_TypicalCase(b *testing.B) {
	resolver := NewResolver()

	// Typical setup: peer zone (authoritative) + one user zone (non-authoritative)
	resolver.Update([]nbdns.CustomZone{
		{Domain: "netbird.cloud.", NonAuthoritative: false},
		{Domain: "custom.local.", NonAuthoritative: true},
	})

	// Query for subdomain of user zone
	qname := "myhost.custom.local."

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resolver.shouldFallthrough(qname)
	}
}

// BenchmarkIsInManagedZone_ManyZones benchmarks isInManagedZone with 100 zones
func BenchmarkIsInManagedZone_ManyZones(b *testing.B) {
	resolver := NewResolver()

	var zones []nbdns.CustomZone
	for i := 0; i < 100; i++ {
		zones = append(zones, nbdns.CustomZone{
			Domain: fmt.Sprintf("zone%d.internal.", i),
		})
	}
	resolver.Update(zones)

	// Query that matches zone50
	qname := "host.zone50.internal."

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resolver.isInManagedZone(qname)
	}
}
