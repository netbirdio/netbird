package dns

import (
	"context"
	"github.com/miekg/dns"
	"strings"
	"testing"
	"time"
)

func TestUpstreamResolver_ServeDNS(t *testing.T) {

	testCases := []struct {
		name                string
		inputMSG            *dns.Msg
		responseShouldBeNil bool
		InputServers        []string
		timeout             time.Duration
		cancelCTX           bool
		expectedAnswer      string
	}{
		{
			name:           "Should Resolve A Record",
			inputMSG:       new(dns.Msg).SetQuestion("one.one.one.one.", dns.TypeA),
			InputServers:   []string{"8.8.8.8:53", "8.8.4.4:53"},
			timeout:        defaultUpstreamTimeout,
			expectedAnswer: "1.1.1.1",
		},
		{
			name:           "Should Resolve If First Upstream Times Out",
			inputMSG:       new(dns.Msg).SetQuestion("one.one.one.one.", dns.TypeA),
			InputServers:   []string{"8.0.0.0:53", "8.8.4.4:53"},
			timeout:        2 * time.Second,
			expectedAnswer: "1.1.1.1",
		},
		{
			name:                "Should Not Resolve If Can't Connect To Both Servers",
			inputMSG:            new(dns.Msg).SetQuestion("one.one.one.one.", dns.TypeA),
			InputServers:        []string{"8.0.0.0:53", "8.0.0.1:53"},
			timeout:             200 * time.Millisecond,
			responseShouldBeNil: true,
		},
		{
			name:                "Should Not Resolve If Parent Context Is Canceled",
			inputMSG:            new(dns.Msg).SetQuestion("one.one.one.one.", dns.TypeA),
			InputServers:        []string{"8.0.0.0:53", "8.8.4.4:53"},
			cancelCTX:           true,
			timeout:             defaultUpstreamTimeout,
			responseShouldBeNil: true,
		},
		//{
		//	name:        "Should Resolve CNAME Record",
		//	inputMSG:    new(dns.Msg).SetQuestion("one.one.one.one", dns.TypeCNAME),
		//},
		//{
		//	name:                "Should Not Write When Not Found A Record",
		//	inputMSG:            new(dns.Msg).SetQuestion("not.found.com", dns.TypeA),
		//	responseShouldBeNil: true,
		//},
	}
	// should resolve if first upstream times out
	// should not write when both fails
	// should not resolve if parent context is canceled

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.TODO())
			resolver := &upstreamResolver{
				parentCTX:       ctx,
				upstreamClient:  &dns.Client{},
				upstreamServers: testCase.InputServers,
				upstreamTimeout: testCase.timeout,
			}
			if testCase.cancelCTX {
				cancel()
			} else {
				defer cancel()
			}

			var responseMSG *dns.Msg
			responseWriter := &mockResponseWriter{
				WriteMsgFunc: func(m *dns.Msg) error {
					responseMSG = m
					return nil
				},
			}

			resolver.ServeDNS(responseWriter, testCase.inputMSG)

			if responseMSG == nil {
				if testCase.responseShouldBeNil {
					return
				}
				t.Fatalf("should write a response message")
			}

			foundAnswer := false
			for _, answer := range responseMSG.Answer {
				if strings.Contains(answer.String(), testCase.expectedAnswer) {
					foundAnswer = true
					break
				}
			}

			if !foundAnswer {
				t.Errorf("couldn't find the required answer, %s, in the dns response", testCase.expectedAnswer)
			}
		})
	}
}
