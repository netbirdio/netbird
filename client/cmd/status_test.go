package cmd

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/version"
)

func init() {
	loc, err := time.LoadLocation("UTC")
	if err != nil {
		panic(err)
	}

	time.Local = loc
}

var resp = &proto.StatusResponse{
	Status: "Connected",
	FullStatus: &proto.FullStatus{
		Peers: []*proto.PeerState{
			{
				IP:                     "192.168.178.101",
				PubKey:                 "Pubkey1",
				Fqdn:                   "peer-1.awesome-domain.com",
				ConnStatus:             "Connected",
				ConnStatusUpdate:       timestamppb.New(time.Date(2001, time.Month(1), 1, 1, 1, 1, 0, time.UTC)),
				Relayed:                false,
				Direct:                 true,
				LocalIceCandidateType:  "",
				RemoteIceCandidateType: "",
			},
			{
				IP:                     "192.168.178.102",
				PubKey:                 "Pubkey2",
				Fqdn:                   "peer-2.awesome-domain.com",
				ConnStatus:             "Connected",
				ConnStatusUpdate:       timestamppb.New(time.Date(2002, time.Month(2), 2, 2, 2, 2, 0, time.UTC)),
				Relayed:                true,
				Direct:                 false,
				LocalIceCandidateType:  "relay",
				RemoteIceCandidateType: "prflx",
			},
		},
		ManagementState: &proto.ManagementState{
			URL:       "my-awesome-management.com:443",
			Connected: true,
		},
		SignalState: &proto.SignalState{
			URL:       "my-awesome-signal.com:443",
			Connected: true,
		},
		LocalPeerState: &proto.LocalPeerState{
			IP:              "192.168.178.100/16",
			PubKey:          "Some-Pub-Key",
			KernelInterface: true,
			Fqdn:            "some-localhost.awesome-domain.com",
		},
	},
	DaemonVersion: "0.14.1",
}

var overview = statusOutputOverview{
	Peers: peersStateOutput{
		Total:     2,
		Connected: 2,
		Details: []peerStateDetailOutput{
			{
				IP:               "192.168.178.101",
				PubKey:           "Pubkey1",
				FQDN:             "peer-1.awesome-domain.com",
				Status:           "Connected",
				LastStatusUpdate: time.Date(2001, 1, 1, 1, 1, 1, 0, time.UTC),
				ConnType:         "P2P",
				Direct:           true,
				IceCandidateType: iceCandidateType{
					Local:  "",
					Remote: "",
				},
			},
			{
				IP:               "192.168.178.102",
				PubKey:           "Pubkey2",
				FQDN:             "peer-2.awesome-domain.com",
				Status:           "Connected",
				LastStatusUpdate: time.Date(2002, 2, 2, 2, 2, 2, 0, time.UTC),
				ConnType:         "Relayed",
				Direct:           false,
				IceCandidateType: iceCandidateType{
					Local:  "relay",
					Remote: "prflx",
				},
			},
		},
	},
	CliVersion:    version.NetbirdVersion(),
	DaemonVersion: "0.14.1",
	ManagementState: managementStateOutput{
		URL:       "my-awesome-management.com:443",
		Connected: true,
	},
	SignalState: signalStateOutput{
		URL:       "my-awesome-signal.com:443",
		Connected: true,
	},
	IP:              "192.168.178.100/16",
	PubKey:          "Some-Pub-Key",
	KernelInterface: true,
	FQDN:            "some-localhost.awesome-domain.com",
}

func TestConversionFromFullStatusToOutputOverview(t *testing.T) {
	convertedResult := convertToStatusOutputOverview(resp)

	assert.Equal(t, overview, convertedResult)
}

func TestSortingOfPeers(t *testing.T) {
	peers := []peerStateDetailOutput{
		{
			IP: "192.168.178.104",
		},
		{
			IP: "192.168.178.102",
		},
		{
			IP: "192.168.178.101",
		},
		{
			IP: "192.168.178.105",
		},
		{
			IP: "192.168.178.103",
		},
	}

	sortPeersByIP(peers)

	assert.Equal(t, peers[3].IP, "192.168.178.104")
}

func TestParsingToJSON(t *testing.T) {
	json, _ := parseToJSON(overview)

	//@formatter:off
	expectedJSON := "{\"" +
		"peers\":" +
		"{" +
		"\"total\":2," +
		"\"connected\":2," +
		"\"details\":" +
		"[" +
		"{" +
		"\"fqdn\":\"peer-1.awesome-domain.com\"," +
		"\"netbirdIp\":\"192.168.178.101\"," +
		"\"publicKey\":\"Pubkey1\"," +
		"\"status\":\"Connected\"," +
		"\"lastStatusUpdate\":\"2001-01-01T01:01:01Z\"," +
		"\"connectionType\":\"P2P\"," +
		"\"direct\":true," +
		"\"iceCandidateType\":" +
		"{" +
		"\"local\":\"\"," +
		"\"remote\":\"\"" +
		"}" +
		"}," +
		"{" +
		"\"fqdn\":\"peer-2.awesome-domain.com\"," +
		"\"netbirdIp\":\"192.168.178.102\"," +
		"\"publicKey\":\"Pubkey2\"," +
		"\"status\":\"Connected\"," +
		"\"lastStatusUpdate\":\"2002-02-02T02:02:02Z\"," +
		"\"connectionType\":\"Relayed\"," +
		"\"direct\":false," +
		"\"iceCandidateType\":" +
		"{" +
		"\"local\":\"relay\"," +
		"\"remote\":\"prflx\"" +
		"}" +
		"}" +
		"]" +
		"}," +
		"\"cliVersion\":\"development\"," +
		"\"daemonVersion\":\"0.14.1\"," +
		"\"management\":" +
		"{" +
		"\"url\":\"my-awesome-management.com:443\"," +
		"\"connected\":true" +
		"}," +
		"\"signal\":" +
		"{\"" +
		"url\":\"my-awesome-signal.com:443\"," +
		"\"connected\":true" +
		"}," +
		"\"netbirdIp\":\"192.168.178.100/16\"," +
		"\"publicKey\":\"Some-Pub-Key\"," +
		"\"usesKernelInterface\":true," +
		"\"fqdn\":\"some-localhost.awesome-domain.com\"" +
		"}"
	// @formatter:on

	assert.Equal(t, expectedJSON, json)
}

func TestParsingToYAML(t *testing.T) {
	yaml, _ := parseToYAML(overview)

	expectedYAML := "peers:\n" +
		"    total: 2\n" +
		"    connected: 2\n" +
		"    details:\n" +
		"        - fqdn: peer-1.awesome-domain.com\n" +
		"          netbirdIp: 192.168.178.101\n" +
		"          publicKey: Pubkey1\n" +
		"          status: Connected\n" +
		"          lastStatusUpdate: 2001-01-01T01:01:01Z\n" +
		"          connectionType: P2P\n" +
		"          direct: true\n" +
		"          iceCandidateType:\n" +
		"            local: \"\"\n" +
		"            remote: \"\"\n" +
		"        - fqdn: peer-2.awesome-domain.com\n" +
		"          netbirdIp: 192.168.178.102\n" +
		"          publicKey: Pubkey2\n" +
		"          status: Connected\n" +
		"          lastStatusUpdate: 2002-02-02T02:02:02Z\n" +
		"          connectionType: Relayed\n" +
		"          direct: false\n" +
		"          iceCandidateType:\n" +
		"            local: relay\n" +
		"            remote: prflx\n" +
		"cliVersion: development\n" +
		"daemonVersion: 0.14.1\n" +
		"management:\n" +
		"    url: my-awesome-management.com:443\n" +
		"    connected: true\n" +
		"signal:\n" +
		"    url: my-awesome-signal.com:443\n" +
		"    connected: true\n" +
		"netbirdIp: 192.168.178.100/16\n" +
		"publicKey: Some-Pub-Key\n" +
		"usesKernelInterface: true\n" +
		"fqdn: some-localhost.awesome-domain.com\n"

	assert.Equal(t, expectedYAML, yaml)
}

func TestParsingToDetail(t *testing.T) {
	detail := parseToFullDetailSummary(overview)

	expectedDetail := "Peers detail:\n" +
		" peer-1.awesome-domain.com:\n" +
		"  NetBird IP: 192.168.178.101\n" +
		"  Public key: Pubkey1\n" +
		"  Status: Connected\n" +
		"  -- detail --\n" +
		"  Connection type: P2P\n" +
		"  Direct: true\n" +
		"  ICE candidate (Local/Remote): -/-\n" +
		"  Last connection update: 2001-01-01 01:01:01\n" +
		"\n" +
		" peer-2.awesome-domain.com:\n" +
		"  NetBird IP: 192.168.178.102\n" +
		"  Public key: Pubkey2\n" +
		"  Status: Connected\n" +
		"  -- detail --\n" +
		"  Connection type: Relayed\n" +
		"  Direct: false\n" +
		"  ICE candidate (Local/Remote): relay/prflx\n" +
		"  Last connection update: 2002-02-02 02:02:02\n" +
		"\n" +
		"Daemon version: 0.14.1\n" +
		"CLI version: development\n" +
		"Management: Connected to my-awesome-management.com:443\n" +
		"Signal: Connected to my-awesome-signal.com:443\n" +
		"FQDN: some-localhost.awesome-domain.com\n" +
		"NetBird IP: 192.168.178.100/16\n" +
		"Interface type: Kernel\n" +
		"Peers count: 2/2 Connected\n"

	assert.Equal(t, expectedDetail, detail)
}

func TestParsingToShortVersion(t *testing.T) {
	shortVersion := parseGeneralSummary(overview, false)

	expectedString := "Daemon version: 0.14.1\n" +
		"CLI version: development\n" +
		"Management: Connected\n" +
		"Signal: Connected\n" +
		"FQDN: some-localhost.awesome-domain.com\n" +
		"NetBird IP: 192.168.178.100/16\n" +
		"Interface type: Kernel\n" +
		"Peers count: 2/2 Connected\n"

	assert.Equal(t, expectedString, shortVersion)
}

func TestParsingOfIP(t *testing.T) {
	InterfaceIP := "192.168.178.123/16"

	parsedIP := parseInterfaceIP(InterfaceIP)

	assert.Equal(t, "192.168.178.123\n", parsedIP)
}
