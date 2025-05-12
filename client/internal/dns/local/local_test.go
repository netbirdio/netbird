package local

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/dns/test"
	nbdns "github.com/netbirdio/netbird/dns"
)

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
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			resolver := NewResolver()
			_ = resolver.RegisterRecord(testCase.inputRecord)
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
			if !strings.Contains(answerString, testCase.inputRecord.Name) {
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

	update1 := []nbdns.SimpleRecord{record1}
	update2 := []nbdns.SimpleRecord{record2}

	// Apply first update
	resolver.Update(update1)

	// Verify first update
	resolver.mu.RLock()
	rrSlice1, found1 := resolver.records[recordKey]
	resolver.mu.RUnlock()

	require.True(t, found1, "Record key %s not found after first update", recordKey)
	require.Len(t, rrSlice1, 1, "Should have exactly 1 record after first update")
	assert.Contains(t, rrSlice1[0].String(), record1.RData, "Record after first update should be %s", record1.RData)

	// Apply second update
	resolver.Update(update2)

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

	update := []nbdns.SimpleRecord{record1, record2}

	// Apply update with both records
	resolver.Update(update)

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

	update := []nbdns.SimpleRecord{record1, record2, record3}

	// Apply update with all three records
	resolver.Update(update)

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
	resolver.Update([]nbdns.SimpleRecord{lowerCaseRecord, mixedCaseRecord})

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
	resolver.Update([]nbdns.SimpleRecord{cnameRecord, targetRecord})

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
