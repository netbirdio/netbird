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
