package cmd

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
				IP:                         "192.168.178.101",
				PubKey:                     "Pubkey1",
				Fqdn:                       "peer-1.awesome-domain.com",
				ConnStatus:                 "Connected",
				ConnStatusUpdate:           timestamppb.New(time.Date(2001, time.Month(1), 1, 1, 1, 1, 0, time.UTC)),
				Relayed:                    false,
				Direct:                     true,
				LocalIceCandidateType:      "",
				RemoteIceCandidateType:     "",
				LocalIceCandidateEndpoint:  "",
				RemoteIceCandidateEndpoint: "",
				LastWireguardHandshake:     timestamppb.New(time.Date(2001, time.Month(1), 1, 1, 1, 2, 0, time.UTC)),
				BytesRx:                    200,
				BytesTx:                    100,
			},
			{
				IP:                         "192.168.178.102",
				PubKey:                     "Pubkey2",
				Fqdn:                       "peer-2.awesome-domain.com",
				ConnStatus:                 "Connected",
				ConnStatusUpdate:           timestamppb.New(time.Date(2002, time.Month(2), 2, 2, 2, 2, 0, time.UTC)),
				Relayed:                    true,
				Direct:                     false,
				LocalIceCandidateType:      "relay",
				RemoteIceCandidateType:     "prflx",
				LocalIceCandidateEndpoint:  "10.0.0.1:10001",
				RemoteIceCandidateEndpoint: "10.0.10.1:10002",
				LastWireguardHandshake:     timestamppb.New(time.Date(2002, time.Month(2), 2, 2, 2, 3, 0, time.UTC)),
				BytesRx:                    2000,
				BytesTx:                    1000,
			},
		},
		ManagementState: &proto.ManagementState{
			URL:       "my-awesome-management.com:443",
			Connected: true,
			Error:     "",
		},
		SignalState: &proto.SignalState{
			URL:       "my-awesome-signal.com:443",
			Connected: true,
			Error:     "",
		},
		Relays: []*proto.RelayState{
			{
				URI:       "stun:my-awesome-stun.com:3478",
				Available: true,
				Error:     "",
			},
			{
				URI:       "turns:my-awesome-turn.com:443?transport=tcp",
				Available: false,
				Error:     "context: deadline exceeded",
			},
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
				IceCandidateEndpoint: iceCandidateType{
					Local:  "",
					Remote: "",
				},
				LastWireguardHandshake: time.Date(2001, 1, 1, 1, 1, 2, 0, time.UTC),
				TransferReceived:       200,
				TransferSent:           100,
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
				IceCandidateEndpoint: iceCandidateType{
					Local:  "10.0.0.1:10001",
					Remote: "10.0.10.1:10002",
				},
				LastWireguardHandshake: time.Date(2002, 2, 2, 2, 2, 3, 0, time.UTC),
				TransferReceived:       2000,
				TransferSent:           1000,
			},
		},
	},
	CliVersion:    version.NetbirdVersion(),
	DaemonVersion: "0.14.1",
	ManagementState: managementStateOutput{
		URL:       "my-awesome-management.com:443",
		Connected: true,
		Error:     "",
	},
	SignalState: signalStateOutput{
		URL:       "my-awesome-signal.com:443",
		Connected: true,
		Error:     "",
	},
	Relays: relayStateOutput{
		Total:     2,
		Available: 1,
		Details: []relayStateOutputDetail{
			{
				URI:       "stun:my-awesome-stun.com:3478",
				Available: true,
				Error:     "",
			},
			{
				URI:       "turns:my-awesome-turn.com:443?transport=tcp",
				Available: false,
				Error:     "context: deadline exceeded",
			},
		},
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
	jsonString, _ := parseToJSON(overview)

	//@formatter:off
	expectedJSONString := `
        {
          "peers": {
            "total": 2,
            "connected": 2,
            "details": [
              {
                "fqdn": "peer-1.awesome-domain.com",
                "netbirdIp": "192.168.178.101",
                "publicKey": "Pubkey1",
                "status": "Connected",
                "lastStatusUpdate": "2001-01-01T01:01:01Z",
                "connectionType": "P2P",
                "direct": true,
                "iceCandidateType": {
                  "local": "",
                  "remote": ""
                },
                "iceCandidateEndpoint": {
                  "local": "",
                  "remote": ""
                },
                "lastWireguardHandshake": "2001-01-01T01:01:02Z",
                "transferReceived": 200,
                "transferSent": 100
              },
              {
                "fqdn": "peer-2.awesome-domain.com",
                "netbirdIp": "192.168.178.102",
                "publicKey": "Pubkey2",
                "status": "Connected",
                "lastStatusUpdate": "2002-02-02T02:02:02Z",
                "connectionType": "Relayed",
                "direct": false,
                "iceCandidateType": {
                  "local": "relay",
                  "remote": "prflx"
                },
                "iceCandidateEndpoint": {
                  "local": "10.0.0.1:10001",
                  "remote": "10.0.10.1:10002"
                },
                "lastWireguardHandshake": "2002-02-02T02:02:03Z",
                "transferReceived": 2000,
                "transferSent": 1000
              }
            ]
          },
          "cliVersion": "development",
          "daemonVersion": "0.14.1",
          "management": {
            "url": "my-awesome-management.com:443",
            "connected": true,
            "error": ""
          },
          "signal": {
            "url": "my-awesome-signal.com:443",
            "connected": true,
            "error": ""
          },
          "relays": {
            "total": 2,
            "available": 1,
            "details": [
              {
                "uri": "stun:my-awesome-stun.com:3478",
                "available": true,
                "error": ""
              },
              {
                "uri": "turns:my-awesome-turn.com:443?transport=tcp",
                "available": false,
                "error": "context: deadline exceeded"
              }
            ]
          },
          "netbirdIp": "192.168.178.100/16",
          "publicKey": "Some-Pub-Key",
          "usesKernelInterface": true,
          "fqdn": "some-localhost.awesome-domain.com"
        }`
	// @formatter:on

	var expectedJSON bytes.Buffer
	require.NoError(t, json.Compact(&expectedJSON, []byte(expectedJSONString)))

	assert.Equal(t, expectedJSON.String(), jsonString)
}

func TestParsingToYAML(t *testing.T) {
	yaml, _ := parseToYAML(overview)

	expectedYAML :=
		`peers:
    total: 2
    connected: 2
    details:
        - fqdn: peer-1.awesome-domain.com
          netbirdIp: 192.168.178.101
          publicKey: Pubkey1
          status: Connected
          lastStatusUpdate: 2001-01-01T01:01:01Z
          connectionType: P2P
          direct: true
          iceCandidateType:
            local: ""
            remote: ""
          iceCandidateEndpoint:
            local: ""
            remote: ""
          lastWireguardHandshake: 2001-01-01T01:01:02Z
          transferReceived: 200
          transferSent: 100
        - fqdn: peer-2.awesome-domain.com
          netbirdIp: 192.168.178.102
          publicKey: Pubkey2
          status: Connected
          lastStatusUpdate: 2002-02-02T02:02:02Z
          connectionType: Relayed
          direct: false
          iceCandidateType:
            local: relay
            remote: prflx
          iceCandidateEndpoint:
            local: 10.0.0.1:10001
            remote: 10.0.10.1:10002
          lastWireguardHandshake: 2002-02-02T02:02:03Z
          transferReceived: 2000
          transferSent: 1000
cliVersion: development
daemonVersion: 0.14.1
management:
    url: my-awesome-management.com:443
    connected: true
    error: ""
signal:
    url: my-awesome-signal.com:443
    connected: true
    error: ""
relays:
    total: 2
    available: 1
    details:
        - uri: stun:my-awesome-stun.com:3478
          available: true
          error: ""
        - uri: turns:my-awesome-turn.com:443?transport=tcp
          available: false
          error: 'context: deadline exceeded'
netbirdIp: 192.168.178.100/16
publicKey: Some-Pub-Key
usesKernelInterface: true
fqdn: some-localhost.awesome-domain.com
`

	assert.Equal(t, expectedYAML, yaml)
}

func TestParsingToDetail(t *testing.T) {
	detail := parseToFullDetailSummary(overview)

	expectedDetail :=
		`Peers detail:
 peer-1.awesome-domain.com:
  NetBird IP: 192.168.178.101
  Public key: Pubkey1
  Status: Connected
  -- detail --
  Connection type: P2P
  Direct: true
  ICE candidate (Local/Remote): -/-
  ICE candidate endpoints (Local/Remote): -/-
  Last connection update: 2001-01-01 01:01:01
  Last Wireguard handshake: 2001-01-01 01:01:02
  Transfer status (received/sent) 200 B/100 B

 peer-2.awesome-domain.com:
  NetBird IP: 192.168.178.102
  Public key: Pubkey2
  Status: Connected
  -- detail --
  Connection type: Relayed
  Direct: false
  ICE candidate (Local/Remote): relay/prflx
  ICE candidate endpoints (Local/Remote): 10.0.0.1:10001/10.0.10.1:10002
  Last connection update: 2002-02-02 02:02:02
  Last Wireguard handshake: 2002-02-02 02:02:03
  Transfer status (received/sent) 2.0 KiB/1000 B

Daemon version: 0.14.1
CLI version: development
Management: Connected to my-awesome-management.com:443
Signal: Connected to my-awesome-signal.com:443
Relays: 
  [stun:my-awesome-stun.com:3478] is Available
  [turns:my-awesome-turn.com:443?transport=tcp] is Unavailable, reason: context: deadline exceeded
FQDN: some-localhost.awesome-domain.com
NetBird IP: 192.168.178.100/16
Interface type: Kernel
Peers count: 2/2 Connected
`

	assert.Equal(t, expectedDetail, detail)
}

func TestParsingToShortVersion(t *testing.T) {
	shortVersion := parseGeneralSummary(overview, false, false)

	expectedString :=
		`Daemon version: 0.14.1
CLI version: development
Management: Connected
Signal: Connected
Relays: 1/2 Available
FQDN: some-localhost.awesome-domain.com
NetBird IP: 192.168.178.100/16
Interface type: Kernel
Peers count: 2/2 Connected
`

	assert.Equal(t, expectedString, shortVersion)
}

func TestParsingOfIP(t *testing.T) {
	InterfaceIP := "192.168.178.123/16"

	parsedIP := parseInterfaceIP(InterfaceIP)

	assert.Equal(t, "192.168.178.123\n", parsedIP)
}
