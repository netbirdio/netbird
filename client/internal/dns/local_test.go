package dns

import (
	"strings"
	"testing"

	"github.com/miekg/dns"

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
			resolver := &localResolver{
				registeredMap: make(registrationMap),
			}
			_ = resolver.registerRecord(testCase.inputRecord)
			var responseMSG *dns.Msg
			responseWriter := &mockResponseWriter{
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
