package peer

import (
	"sync"
	"testing"
	"time"

	"github.com/magiconair/properties/assert"
	"github.com/pion/ice/v2"

	"github.com/netbirdio/netbird/client/internal/proxy"
	"github.com/netbirdio/netbird/iface"
)

var connConf = ConnConfig{
	Key:                "LLHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU=",
	LocalKey:           "RRHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU=",
	StunTurn:           []*ice.URL{},
	InterfaceBlackList: nil,
	Timeout:            time.Second,
	ProxyConfig:        proxy.Config{},
	LocalWgPort:        51820,
}

func TestNewConn_interfaceFilter(t *testing.T) {
	ignore := []string{iface.WgInterfaceDefault, "tun0", "zt", "ZeroTier", "utun", "wg", "ts",
		"Tailscale", "tailscale"}

	filter := interfaceFilter(ignore)

	for _, s := range ignore {
		assert.Equal(t, filter(s), false)
	}

}

func TestConn_GetKey(t *testing.T) {
	conn, err := NewConn(connConf, nil)
	if err != nil {
		return
	}

	got := conn.GetKey()

	assert.Equal(t, got, connConf.Key, "they should be equal")
}

func TestConn_OnRemoteOffer(t *testing.T) {

	conn, err := NewConn(connConf, NewRecorder())
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

	conn, err := NewConn(connConf, NewRecorder())
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

	conn, err := NewConn(connConf, NewRecorder())
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

	conn, err := NewConn(connConf, NewRecorder())
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
			name: "Use Proxy When Local Candidate Is Relay",
			candatePair: &ice.CandidatePair{
				Local:  relayCandidate,
				Remote: privateHostCandidate,
			},
			expected: true,
		},
		{
			name: "Use Proxy When Remote Candidate Is Relay",
			candatePair: &ice.CandidatePair{
				Local:  privateHostCandidate,
				Remote: relayCandidate,
			},
			expected: true,
		},
		{
			name: "Use Proxy When Local Candidate Is Peer Reflexive",
			candatePair: &ice.CandidatePair{
				Local:  prflxCandidate,
				Remote: privateHostCandidate,
			},
			expected: true,
		},
		{
			name: "Use Proxy When Remote Candidate Is Peer Reflexive",
			candatePair: &ice.CandidatePair{
				Local:  privateHostCandidate,
				Remote: prflxCandidate,
			},
			expected: true,
		},
		{
			name: "Don't Use Proxy When Local Candidate Is Public And Remote Is Private",
			candatePair: &ice.CandidatePair{
				Local:  publicHostCandidate,
				Remote: privateHostCandidate,
			},
			expected: false,
		},
		{
			name: "Don't Use Proxy When Remote Candidate Is Public And Local Is Private",
			candatePair: &ice.CandidatePair{
				Local:  privateHostCandidate,
				Remote: publicHostCandidate,
			},
			expected: false,
		},
		{
			name: "Don't Use Proxy When Local Candidate is Public And Remote Is Server Reflexive",
			candatePair: &ice.CandidatePair{
				Local:  publicHostCandidate,
				Remote: srflxCandidate,
			},
			expected: false,
		},
		{
			name: "Don't Use Proxy When Remote Candidate is Public And Local Is Server Reflexive",
			candatePair: &ice.CandidatePair{
				Local:  srflxCandidate,
				Remote: publicHostCandidate,
			},
			expected: false,
		},
		{
			name: "Don't Use Proxy When Both Candidates Are Public",
			candatePair: &ice.CandidatePair{
				Local:  publicHostCandidate,
				Remote: publicHostCandidate,
			},
			expected: false,
		},
		{
			name: "Don't Use Proxy When Both Candidates Are Private",
			candatePair: &ice.CandidatePair{
				Local:  privateHostCandidate,
				Remote: privateHostCandidate,
			},
			expected: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			result := shouldUseProxy(testCase.candatePair)
			if result != testCase.expected {
				t.Errorf("got a different result. Expected %t Got %t", testCase.expected, result)
			}
		})
	}
}
