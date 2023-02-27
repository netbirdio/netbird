package cmd

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/client/system"
)

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
				LocalIceCandidateType:  "-",
				RemoteIceCandidateType: "-",
			},
			{
				IP:                     "192.168.178.102",
				PubKey:                 "Pubkey2",
				Fqdn:                   "peer-2.awesome-domain.com",
				ConnStatus:             "Connected",
				ConnStatusUpdate:       timestamppb.New(time.Date(2002, time.Month(2), 2, 2, 2, 2, 0, time.UTC)),
				Relayed:                true,
				Direct:                 false,
				LocalIceCandidateType:  "-",
				RemoteIceCandidateType: "-",
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
				IP:                     "192.168.178.101",
				PubKey:                 "Pubkey1",
				FQDN:                   "peer-1.awesome-domain.com",
				ConnStatus:             "Connected",
				ConnStatusUpdate:       time.Date(2001, 1, 1, 1, 1, 1, 0, time.UTC),
				ConnType:               "P2P",
				Direct:                 true,
				LocalIceCandidateType:  "-",
				RemoteIceCandidateType: "-",
			},
			{
				IP:                     "192.168.178.102",
				PubKey:                 "Pubkey2",
				FQDN:                   "peer-2.awesome-domain.com",
				ConnStatus:             "Connected",
				ConnStatusUpdate:       time.Date(2002, 2, 2, 2, 2, 2, 0, time.UTC),
				ConnType:               "Relayed",
				Direct:                 false,
				LocalIceCandidateType:  "-",
				RemoteIceCandidateType: "-",
			},
		},
	},
	CliVersion:    system.NetbirdVersion(),
	DaemonVersion: "0.14.1",
	DaemonStatus:  "Connected",
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
	KernelInterface: "Kernel",
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

	sortPeersByIp(peers)

	assert.Equal(t, peers[3].IP, "192.168.178.104")
}

func TestParsingToJson(t *testing.T) {
	json, _ := parseToJson(overview)

	// @formatter:off
	expectedJson := "{" +
		"\"peers\":" +
		"{" +
		"\"total\":2," +
		"\"connected\":2," +
		"\"details\":" +
		"[" +
		"{" +
		"\"ip\":\"192.168.178.101\"," +
		"\"publicKey\":\"Pubkey1\"," +
		"\"fqdn\":\"peer-1.awesome-domain.com\"," +
		"\"connectionStatus\":\"Connected\"" +
		",\"connectionStatusUpdate\":\"2001-01-01T01:01:01Z\"," +
		"\"connectionType\":\"P2P\"," +
		"\"direct\":true," +
		"\"localIceCandidateType\":\"-\"," +
		"\"remoteIceCandidateType\":\"-\"" +
		"}," +
		"{" +
		"\"ip\":\"192.168.178.102\"," +
		"\"publicKey\":\"Pubkey2\"," +
		"\"fqdn\":\"peer-2.awesome-domain.com\"," +
		"\"connectionStatus\":\"Connected\"," +
		"\"connectionStatusUpdate\":\"2002-02-02T02:02:02Z\"," +
		"\"connectionType\":\"Relayed\"," +
		"\"direct\":false," +
		"\"localIceCandidateType\":\"-\"," +
		"\"remoteIceCandidateType\":\"-\"" +
		"}" +
		"]" +
		"}," +
		"\"cliVersion\":\"development\"," +
		"\"daemonVersion\":\"0.14.1\"," +
		"\"daemonStatus\":\"Connected\"," +
		"\"management\":" +
		"{" +
		"\"url\":\"my-awesome-management.com:443\"," +
		"\"connected\":true" +
		"}," +
		"\"signal\":" +
		"{" +
		"\"url\":\"my-awesome-signal.com:443\"," +
		"\"connected\":true" +
		"}," +
		"\"ip\":\"192.168.178.100/16\"," +
		"\"publicKey\":\"Some-Pub-Key\"," +
		"\"interfaceType\":\"Kernel\"," +
		"\"domain\":\"some-localhost.awesome-domain.com\"" +
		"}"
	// @formatter:on

	assert.Equal(t, expectedJson, json)
}

func TestParsingToYaml(t *testing.T) {
	yaml, _ := parseToYaml(overview)

	expectedYaml := "peers:\n" +
		"    total: 2\n" +
		"    connected: 2\n" +
		"    details:\n" +
		"        - ip: 192.168.178.101\n" +
		"          publicKey: Pubkey1\n" +
		"          fqdn: peer-1.awesome-domain.com\n" +
		"          connectionStatus: Connected\n" +
		"          connectionStatusUpdate: 2001-01-01T01:01:01Z\n" +
		"          connectionType: P2P\n" +
		"          direct: true\n" +
		"          localIceCandidateType: '-'\n" +
		"          remoteIceCandidateType: '-'\n" +
		"        - ip: 192.168.178.102\n" +
		"          publicKey: Pubkey2\n" +
		"          fqdn: peer-2.awesome-domain.com\n" +
		"          connectionStatus: Connected\n" +
		"          connectionStatusUpdate: 2002-02-02T02:02:02Z\n" +
		"          connectionType: Relayed\n" +
		"          direct: false\n" +
		"          localIceCandidateType: '-'\n" +
		"          remoteIceCandidateType: '-'\n" +
		"cliVersion: development\n" +
		"daemonVersion: 0.14.1\n" +
		"daemonStatus: Connected\n" +
		"management:\n" +
		"    url: my-awesome-management.com:443\n" +
		"    connected: true\n" +
		"signal:\n" +
		"    url: my-awesome-signal.com:443\n" +
		"    connected: true\n" +
		"ip: 192.168.178.100/16\n" +
		"publicKey: Some-Pub-Key\n" +
		"interfaceType: Kernel\n" +
		"domain: some-localhost.awesome-domain.com\n"

	assert.Equal(t, expectedYaml, yaml)
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
		"  ICE candidate (Local/Remote): -/-\n" +
		"  Last connection update: 2002-02-02 02:02:02\n" +
		"\n" +
		"Daemon version: 0.14.1\n" +
		"CLI version: development\n" +
		"ConnectedManagement: Connected to my-awesome-management.com:443\n" +
		"Signal: Connected to my-awesome-signal.com:443\n" +
		"Domain: some-localhost.awesome-domain.com\n" +
		"NetBird IP: 192.168.178.100/16\n" +
		"Interface type: Kernel\n" +
		"Peers count: 2/2 Connected\n"

	assert.Equal(t, expectedDetail, detail)
}

func TestParsingToShortVersion(t *testing.T) {
	shortVersion := parseGeneralSummary(overview, false)

	expectedString := "Daemon version: 0.14.1\n" +
		"CLI version: development\n" +
		"ConnectedManagement: Connected\n" +
		"Signal: Connected\n" +
		"Domain: some-localhost.awesome-domain.com\n" +
		"NetBird IP: 192.168.178.100/16\n" +
		"Interface type: Kernel\n" +
		"Peers count: 2/2 Connected\n"

	assert.Equal(t, expectedString, shortVersion)
}

func TestParsingOfIp(t *testing.T) {
	InterfaceIp := "192.168.178.123/16"

	parsedId := parseInterfaceIP(InterfaceIp)

	assert.Equal(t, "192.168.178.123\n", parsedId)
}
