package peer

import (
	"sync"
	"testing"
	"time"

	"github.com/netbirdio/netbird/client/internal/stdnet"

	"github.com/magiconair/properties/assert"
	"github.com/pion/ice/v2"
	"golang.org/x/sync/errgroup"

	"github.com/netbirdio/netbird/iface"
	sproto "github.com/netbirdio/netbird/signal/proto"
)

var connConf = ConnConfig{
	Key:                "LLHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU=",
	LocalKey:           "RRHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU=",
	StunTurn:           []*ice.URL{},
	InterfaceBlackList: nil,
	Timeout:            time.Second,
	WgConfig:           WgConfig{},
	LocalWgPort:        51820,
}

func TestNewConn_interfaceFilter(t *testing.T) {
	ignore := []string{iface.WgInterfaceDefault, "tun0", "zt", "ZeroTier", "utun", "wg", "ts",
		"Tailscale", "tailscale"}

	filter := stdnet.InterfaceFilter(ignore)

	for _, s := range ignore {
		assert.Equal(t, filter(s), false)
	}

}

func TestConn_GetKey(t *testing.T) {
	conn, err := NewConn(connConf, nil, nil, nil)
	if err != nil {
		return
	}

	got := conn.GetKey()

	assert.Equal(t, got, connConf.Key, "they should be equal")
}

func TestConn_OnRemoteOffer(t *testing.T) {

	conn, err := NewConn(connConf, NewRecorder("https://mgm"), nil, nil)
	if err != nil {
		return
	}

	wg := sync.WaitGroup{}
	wg.Add(2)
	go func() {
		<-conn.remoteOffersCh
		wg.Done()
	}()

	go func() {
		for {
			accepted := conn.OnRemoteOffer(OfferAnswer{
				IceCredentials: IceCredentials{
					UFrag: "test",
					Pwd:   "test",
				},
				WgListenPort: 0,
				Version:      "",
			})
			if accepted {
				wg.Done()
				return
			}
		}
	}()

	wg.Wait()
}

func TestConn_OnRemoteAnswer(t *testing.T) {

	conn, err := NewConn(connConf, NewRecorder("https://mgm"), nil, nil)
	if err != nil {
		return
	}

	wg := sync.WaitGroup{}
	wg.Add(2)
	go func() {
		<-conn.remoteAnswerCh
		wg.Done()
	}()

	go func() {
		for {
			accepted := conn.OnRemoteAnswer(OfferAnswer{
				IceCredentials: IceCredentials{
					UFrag: "test",
					Pwd:   "test",
				},
				WgListenPort: 0,
				Version:      "",
			})
			if accepted {
				wg.Done()
				return
			}
		}
	}()

	wg.Wait()
}
func TestConn_Status(t *testing.T) {

	conn, err := NewConn(connConf, NewRecorder("https://mgm"), nil, nil)
	if err != nil {
		return
	}

	tables := []struct {
		name   string
		status ConnStatus
		want   ConnStatus
	}{
		{"StatusConnected", StatusConnected, StatusConnected},
		{"StatusDisconnected", StatusDisconnected, StatusDisconnected},
		{"StatusConnecting", StatusConnecting, StatusConnecting},
	}

	for _, table := range tables {
		t.Run(table.name, func(t *testing.T) {
			conn.status = table.status

			got := conn.Status()
			assert.Equal(t, got, table.want, "they should be equal")
		})
	}
}

func TestConn_Close(t *testing.T) {

	conn, err := NewConn(connConf, NewRecorder("https://mgm"), nil, nil)
	if err != nil {
		return
	}

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		<-conn.closeCh
		wg.Done()
	}()

	go func() {
		for {
			err := conn.Close()
			if err != nil {
				continue
			} else {
				return
			}
		}
	}()

	wg.Wait()
}

type mockICECandidate struct {
	ice.Candidate
	AddressFunc func() string
	TypeFunc    func() ice.CandidateType
}

// Address mocks and overwrite ice.Candidate Address method
func (m *mockICECandidate) Address() string {
	if m.AddressFunc != nil {
		return m.AddressFunc()
	}
	return ""
}

// Type mocks and overwrite ice.Candidate Type method
func (m *mockICECandidate) Type() ice.CandidateType {
	if m.TypeFunc != nil {
		return m.TypeFunc()
	}
	return ice.CandidateTypeUnspecified
}

func TestConn_ShouldUseProxy(t *testing.T) {
	publicHostCandidate := &mockICECandidate{
		AddressFunc: func() string {
			return "8.8.8.8"
		},
		TypeFunc: func() ice.CandidateType {
			return ice.CandidateTypeHost
		},
	}
	privateHostCandidate := &mockICECandidate{
		AddressFunc: func() string {
			return "10.0.0.1"
		},
		TypeFunc: func() ice.CandidateType {
			return ice.CandidateTypeHost
		},
	}

	srflxCandidate := &mockICECandidate{
		AddressFunc: func() string {
			return "1.1.1.1"
		},
		TypeFunc: func() ice.CandidateType {
			return ice.CandidateTypeServerReflexive
		},
	}

	prflxCandidate := &mockICECandidate{
		AddressFunc: func() string {
			return "1.1.1.1"
		},
		TypeFunc: func() ice.CandidateType {
			return ice.CandidateTypePeerReflexive
		},
	}

	relayCandidate := &mockICECandidate{
		AddressFunc: func() string {
			return "1.1.1.1"
		},
		TypeFunc: func() ice.CandidateType {
			return ice.CandidateTypeRelay
		},
	}

	testCases := []struct {
		name        string
		candatePair *ice.CandidatePair
		expected    bool
	}{
		{
			name: "Use proxy When Local Candidate Is Relay",
			candatePair: &ice.CandidatePair{
				Local:  relayCandidate,
				Remote: privateHostCandidate,
			},
			expected: false,
		},
		{
			name: "Use proxy When Remote Candidate Is Relay",
			candatePair: &ice.CandidatePair{
				Local:  privateHostCandidate,
				Remote: relayCandidate,
			},
			expected: false,
		},
		{
			name: "Use proxy When Local Candidate Is Peer Reflexive",
			candatePair: &ice.CandidatePair{
				Local:  prflxCandidate,
				Remote: privateHostCandidate,
			},
			expected: false,
		},
		{
			name: "Use proxy When Remote Candidate Is Peer Reflexive",
			candatePair: &ice.CandidatePair{
				Local:  privateHostCandidate,
				Remote: prflxCandidate,
			},
			expected: false,
		},
		{
			name: "Don't Use proxy When Local Candidate Is Public And Remote Is Private",
			candatePair: &ice.CandidatePair{
				Local:  publicHostCandidate,
				Remote: privateHostCandidate,
			},
			expected: true,
		},
		{
			name: "Don't Use proxy When Remote Candidate Is Public And Local Is Private",
			candatePair: &ice.CandidatePair{
				Local:  privateHostCandidate,
				Remote: publicHostCandidate,
			},
			expected: true,
		},
		{
			name: "Don't Use proxy When Local Candidate is Public And Remote Is Server Reflexive",
			candatePair: &ice.CandidatePair{
				Local:  publicHostCandidate,
				Remote: srflxCandidate,
			},
			expected: true,
		},
		{
			name: "Don't Use proxy When Remote Candidate is Public And Local Is Server Reflexive",
			candatePair: &ice.CandidatePair{
				Local:  srflxCandidate,
				Remote: publicHostCandidate,
			},
			expected: true,
		},
		{
			name: "Don't Use proxy When Both Candidates Are Public",
			candatePair: &ice.CandidatePair{
				Local:  publicHostCandidate,
				Remote: publicHostCandidate,
			},
			expected: true,
		},
		{
			name: "Don't Use proxy When Both Candidates Are Private",
			candatePair: &ice.CandidatePair{
				Local:  privateHostCandidate,
				Remote: privateHostCandidate,
			},
			expected: true,
		},
		{
			name: "Don't Use proxy When Both Candidates are in private network and one is peer reflexive",
			candatePair: &ice.CandidatePair{
				Local: &mockICECandidate{AddressFunc: func() string {
					return "10.16.102.168"
				},
					TypeFunc: func() ice.CandidateType {
						return ice.CandidateTypeHost
					}},
				Remote: &mockICECandidate{AddressFunc: func() string {
					return "10.16.101.96"
				},
					TypeFunc: func() ice.CandidateType {
						return ice.CandidateTypePeerReflexive
					}},
			},
			expected: true,
		},
		{
			name: "Should Use proxy When Both Candidates are in private network and both are peer reflexive",
			candatePair: &ice.CandidatePair{
				Local: &mockICECandidate{AddressFunc: func() string {
					return "10.16.102.168"
				},
					TypeFunc: func() ice.CandidateType {
						return ice.CandidateTypePeerReflexive
					}},
				Remote: &mockICECandidate{AddressFunc: func() string {
					return "10.16.101.96"
				},
					TypeFunc: func() ice.CandidateType {
						return ice.CandidateTypePeerReflexive
					}},
			},
			expected: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			result := isPreferredDirectMode(testCase.candatePair, false)
			if result != testCase.expected {
				t.Errorf("got a different result. Expected %t Got %t", testCase.expected, result)
			}
		})
	}
}

func TestGetProxyWithMessageExchange(t *testing.T) {
	publicHostCandidate := &mockICECandidate{
		AddressFunc: func() string {
			return "8.8.8.8"
		},
		TypeFunc: func() ice.CandidateType {
			return ice.CandidateTypeHost
		},
	}
	relayCandidate := &mockICECandidate{
		AddressFunc: func() string {
			return "1.1.1.1"
		},
		TypeFunc: func() ice.CandidateType {
			return ice.CandidateTypeRelay
		},
	}

	testCases := []struct {
		name                   string
		candatePair            *ice.CandidatePair
		inputDirectModeSupport bool
		inputRemoteModeMessage bool
		expected               bool
	}{
		{
			name: "Should Result In Using Wireguard proxy When Local Eval Is Use proxy",
			candatePair: &ice.CandidatePair{
				Local:  relayCandidate,
				Remote: publicHostCandidate,
			},
			inputDirectModeSupport: true,
			inputRemoteModeMessage: true,
			expected:               true,
		},
		{
			name: "Should Result In Using Wireguard proxy When Remote Eval Is Use proxy",
			candatePair: &ice.CandidatePair{
				Local:  publicHostCandidate,
				Remote: publicHostCandidate,
			},
			inputDirectModeSupport: true,
			inputRemoteModeMessage: false,
			expected:               true,
		},
		{
			name: "Should Result In Using Wireguard proxy When Remote Direct Mode Support Is False And Local Eval Is Use proxy",
			candatePair: &ice.CandidatePair{
				Local:  relayCandidate,
				Remote: publicHostCandidate,
			},
			inputDirectModeSupport: false,
			inputRemoteModeMessage: false,
			expected:               true,
		},
		{
			name: "Should Result In Using Direct When Remote Direct Mode Support Is False And Local Eval Is No Use proxy",
			candatePair: &ice.CandidatePair{
				Local:  publicHostCandidate,
				Remote: publicHostCandidate,
			},
			inputDirectModeSupport: false,
			inputRemoteModeMessage: false,
			expected:               false,
		},
		{
			name: "Should Result In Using Direct When Local And Remote Eval Is No proxy",
			candatePair: &ice.CandidatePair{
				Local:  publicHostCandidate,
				Remote: publicHostCandidate,
			},
			inputDirectModeSupport: true,
			inputRemoteModeMessage: true,
			expected:               false,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			g := errgroup.Group{}
			conn, err := NewConn(connConf, nil, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			conn.meta.protoSupport.DirectCheck = testCase.inputDirectModeSupport
			conn.SetSendSignalMessage(func(message *sproto.Message) error {
				return nil
			})

			g.Go(func() error {
				return conn.OnModeMessage(ModeMessage{
					Direct: testCase.inputRemoteModeMessage,
				})
			})
			conn.config.UserspaceBind = false
			resultProxy := conn.isProxyNeeded(testCase.inputDirectModeSupport, testCase.inputRemoteModeMessage)

			err = g.Wait()
			if err != nil {
				t.Error(err)
			}
			if resultProxy != testCase.expected {
				t.Errorf("result didn't match expected value: Expected: %v, Got: %v", testCase.expected, resultProxy)
			}
		})
	}
}
