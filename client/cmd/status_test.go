package cmd

import (
	nbStatus "github.com/netbirdio/netbird/client/status"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

var fullStatus = nbStatus.FullStatus{
	Peers: []nbStatus.PeerState{
		{
			IP:                     "192.168.178.101",
			PubKey:                 "Pubkey1",
			FQDN:                   "peer-1.awesome-domain.com",
			ConnStatus:             "Connected",
			ConnStatusUpdate:       time.Date(2001, time.Month(1), 1, 1, 1, 1, 0, time.UTC),
			Relayed:                false,
			LocalIceCandidateType:  "-",
			RemoteIceCandidateType: "-",
		},
		{
			IP:                     "192.168.178.102",
			PubKey:                 "Pubkey2",
			FQDN:                   "peer-2.awesome-domain.com",
			ConnStatus:             "Connected",
			ConnStatusUpdate:       time.Date(2002, time.Month(2), 2, 2, 2, 2, 0, time.UTC),
			Relayed:                false,
			LocalIceCandidateType:  "-",
			RemoteIceCandidateType: "-",
		},
	},
	ManagementState: nbStatus.ManagementState{
		URL:       "my-awesome-management.com:443",
		Connected: true,
	},
	SignalState: nbStatus.SignalState{
		URL:       "my-awesome-signal.com:443",
		Connected: true,
	},
	LocalPeerState: nbStatus.LocalPeerState{
		IP:              "192.168.178.2",
		PubKey:          "Some-Pub-Key",
		KernelInterface: false,
		FQDN:            "some-localhost.awesome-domain.com",
	},
}

// @formatter:off
func TestParsingToJson(t *testing.T) {
	json, _ := parseToJson(fullStatus)

	expectedJson := "{" +
		"\"Peers\":" +
		"[" +
		"{" +
		"\"IP\":\"192.168.178.101\"," +
		"\"PubKey\":\"Pubkey1\"," +
		"\"FQDN\":\"peer-1.awesome-domain.com\"," +
		"\"ConnStatus\":\"Connected\"," +
		"\"ConnStatusUpdate\":\"2001-01-01T01:01:01Z\"," +
		"\"Relayed\":false," +
		"\"Direct\":false," +
		"\"LocalIceCandidateType\":\"-\"," +
		"\"RemoteIceCandidateType\":\"-\"" +
		"}," +
		"{" +
		"\"IP\":\"192.168.178.102\"," +
		"\"PubKey\":\"Pubkey2\"," +
		"\"FQDN\":\"peer-2.awesome-domain.com\"," +
		"\"ConnStatus\":\"Connected\"," +
		"\"ConnStatusUpdate\":\"2002-02-02T02:02:02Z\"," +
		"\"Relayed\":false," +
		"\"Direct\":false," +
		"\"LocalIceCandidateType\":\"-\"," +
		"\"RemoteIceCandidateType\":\"-\"" +
		"}" +
		"]," +
		"\"ManagementState\":" +
		"{" +
		"\"URL\":\"my-awesome-management.com:443\"," +
		"\"Connected\":true" +
		"}," +
		"\"SignalState\":" +
		"{" +
		"\"URL\":\"my-awesome-signal.com:443\"," +
		"\"Connected\":true" +
		"}," +
		"\"LocalPeerState\":" +
		"{" +
		"\"IP\":\"192.168.178.2\"," +
		"\"PubKey\":\"Some-Pub-Key\"," +
		"\"KernelInterface\":false," +
		"\"FQDN\":\"some-localhost.awesome-domain.com\"" +
		"}" +
		"}"
	assert.Equal(t, expectedJson, json)
}

func TestParsingToYaml(t *testing.T) {
	yaml, _ := parseToYaml(fullStatus)

	expectedYaml := "peers:\n" +
		"- ip: 192.168.178.101\n" +
		"  pubkey: Pubkey1\n" +
		"  fqdn: peer-1.awesome-domain.com\n" +
		"  connstatus: Connected\n" +
		"  connstatusupdate: 2001-01-01T01:01:01Z\n" +
		"  relayed: false\n" +
		"  direct: false\n" +
		"  localicecandidatetype: '-'\n" +
		"  remoteicecandidatetype: '-'\n" +
		"- ip: 192.168.178.102\n" +
		"  pubkey: Pubkey2\n" +
		"  fqdn: peer-2.awesome-domain.com\n" +
		"  connstatus: Connected\n" +
		"  connstatusupdate: 2002-02-02T02:02:02Z\n" +
		"  relayed: false\n" +
		"  direct: false\n" +
		"  localicecandidatetype: '-'\n" +
		"  remoteicecandidatetype: '-'\n" +
		"managementstate:\n" +
		"  url: my-awesome-management.com:443\n" +
		"  connected: true\n" +
		"signalstate:\n" +
		"  url: my-awesome-signal.com:443\n" +
		"  connected: true\n" +
		"localpeerstate:\n" +
		"  ip: 192.168.178.2\n" +
		"  pubkey: Some-Pub-Key\n" +
		"  kernelinterface: false\n" +
		"  fqdn: some-localhost.awesome-domain.com\n"
	assert.Equal(t, expectedYaml, yaml)
}
