package peer

import (
	"fmt"
	"github.com/pion/ice/v2"
	"github.com/stretchr/testify/assert"
	"github.com/wiretrustee/wiretrustee/client/internal/proxy"
	"net"
	"sync"
	"testing"
	"time"
)

var connConf = ConnConfig{
	Key:                "LLHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU=",
	LocalKey:           "RRHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU=",
	StunTurn:           []*ice.URL{},
	InterfaceBlackList: nil,
	Timeout:            2 * time.Second,
	ProxyConfig:        proxy.Config{},
}

func TestConn_GetKey(t *testing.T) {
	conn, err := NewConn(connConf)
	assert.NoError(t, err)

	got := conn.GetKey()

	assert.Equal(t, got, connConf.Key, "they should be equal")
}

func TestConn_OnRemoteOffer(t *testing.T) {

	conn, err := NewConn(connConf)
	assert.NoError(t, err)

	wg := sync.WaitGroup{}
	wg.Add(2)
	go func() {
		<-conn.remoteOffersCh
		wg.Done()
	}()

	go func() {
		for {
			accepted := conn.OnRemoteOffer(IceCredentials{
				UFrag: "test",
				Pwd:   "test",
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

	conn, err := NewConn(connConf)
	assert.NoError(t, err)

	wg := sync.WaitGroup{}
	wg.Add(2)
	go func() {
		<-conn.remoteAnswerCh
		wg.Done()
	}()

	go func() {
		for {
			accepted := conn.OnRemoteAnswer(IceCredentials{
				UFrag: "test",
				Pwd:   "test",
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

	conn, err := NewConn(connConf)
	assert.NoError(t, err)

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

	conn, err := NewConn(connConf)
	assert.NoError(t, err)

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

func TestConn_sendOffer(t *testing.T) {

	conn, err := NewConn(connConf)
	assert.NoError(t, err)

	signals := 0
	ufrag := ""
	pwd := ""

	tables := []struct {
		name                        string
		signalOffer                 func(u string, p string) error
		getLocalUserCredentialsFunc func() (frag string, pwd string, err error)
		wantUfrag                   string
		wantPwd                     string
		wantError                   bool
		wantSignals                 int
	}{
		{"Happy Scenario", func(u string, p string) error {
			signals = signals + 1
			ufrag = u
			pwd = p
			return nil
		}, func() (frag string, pwd string, err error) {
			return "ufrag", "pwd", nil
		}, "ufrag", "pwd", false, 1,
		},

		{"GetLocalUserCredentials failed", func(u string, p string) error {
			signals++
			ufrag = u
			pwd = p
			return nil
		}, func() (frag string, pwd string, err error) {
			return "", "", fmt.Errorf("forced")
		}, "", "", true, 0,
		},

		{"SignalAnswer failed", func(u string, p string) error {
			return fmt.Errorf("forced")
		}, func() (frag string, pwd string, err error) {
			return "ufrag", "pwd", nil
		}, "", "", true, 0,
		},
	}

	for _, table := range tables {
		t.Run(table.name, func(t *testing.T) {

			signals = 0
			ufrag = ""
			pwd = ""

			conn.SetSignalOffer(table.signalOffer)
			agent := &iceAgentMock{}
			agent.GetLocalUserCredentialsFunc = table.getLocalUserCredentialsFunc
			conn.agent = agent

			err = conn.sendOffer()
			if !table.wantError {
				assert.NoError(t, err)
				assert.Equal(t, ufrag, "ufrag")
				assert.Equal(t, pwd, "pwd")
				assert.Equal(t, signals, 1)
			} else {
				assert.Error(t, err)
				assert.Equal(t, signals, 0)
			}

		})
	}
}

func TestConn_onICECandidate(t *testing.T) {
	conn, err := NewConn(connConf)
	assert.NoError(t, err)

	wg := sync.WaitGroup{}
	wg.Add(1)
	conn.signalCandidate = func(candidate ice.Candidate) error {
		wg.Done()
		return nil
	}

	candidate, err := ice.NewCandidateHost(&ice.CandidateHostConfig{
		Network:   "udp",
		Address:   "192.168.1.1",
		Port:      19216,
		Component: 1,
	})
	assert.NoError(t, err)

	conn.onICECandidate(candidate)
	wg.Wait()
}

func TestConn_Open(t *testing.T) {
	conn, err := NewConn(connConf)
	assert.NoError(t, err)

	signalCandidateWg := sync.WaitGroup{}
	signalCandidateWg.Add(2)
	conn.SetSignalCandidate(func(candidate ice.Candidate) error {
		signalCandidateWg.Done()
		return nil
	})

	signalOfferWg := sync.WaitGroup{}
	signalOfferWg.Add(1)
	conn.SetSignalOffer(func(uFrag string, pwd string) error {
		go func() {
			time.Sleep(time.Second)
			conn.OnRemoteAnswer(IceCredentials{
				UFrag: "remoteUfrag",
				Pwd:   "remotePwd",
			})
			signalOfferWg.Done()
		}()
		return nil
	})
	conn.SetSignalAnswer(func(uFrag string, pwd string) error {
		return nil
	})

	gatherCandidatesWg := sync.WaitGroup{}
	gatherCandidatesWg.Add(1)
	conn.iceAgentProvider = &iceAgentProviderMock{agent: &iceAgentMock{
		CloseFunc:              nil,
		AddRemoteCandidateFunc: nil,
		GatherCandidatesFunc: func() error {

			candidate, err := ice.NewCandidateHost(&ice.CandidateHostConfig{
				Network:   "udp",
				Address:   "192.168.1.1",
				Port:      19216,
				Component: 1,
			})
			assert.NoError(t, err)
			conn.onICECandidate(candidate)
			gatherCandidatesWg.Done()
			return nil
		},
		DialFunc:                          nil,
		AcceptFunc:                        nil,
		OnCandidateFunc:                   nil,
		OnConnectionStateChangeFunc:       nil,
		OnSelectedCandidatePairChangeFunc: nil,
		GetLocalUserCredentialsFunc:       nil,
	}}

	proxyStartWg := sync.WaitGroup{}
	proxyStartWg.Add(1)
	conn.proxyProvider = &proxy.ProviderMock{Proxy: &proxy.Mock{
		StartFunc: func(remoteConn net.Conn) error {
			proxyStartWg.Done()
			return nil
		},
		CloseFunc: func() error {
			return nil
		},
	}}

	go func() {
		err = conn.Open()
		assert.NoError(t, err)
	}()

	signalOfferWg.Wait()
	signalCandidateWg.Wait()
	gatherCandidatesWg.Wait()
	proxyStartWg.Wait()
}

func TestConn_sendAnswer(t *testing.T) {

	conn, err := NewConn(connConf)
	assert.NoError(t, err)

	signals := 0
	ufrag := ""
	pwd := ""

	tables := []struct {
		name                        string
		signalAnswer                func(u string, p string) error
		getLocalUserCredentialsFunc func() (frag string, pwd string, err error)
		wantUfrag                   string
		wantPwd                     string
		wantError                   bool
		wantSignals                 int
	}{
		{"Happy Scenario", func(u string, p string) error {
			signals = signals + 1
			ufrag = u
			pwd = p
			return nil
		}, func() (frag string, pwd string, err error) {
			return "ufrag", "pwd", nil
		}, "ufrag", "pwd", false, 1,
		},

		{"GetLocalUserCredentials failed", func(u string, p string) error {
			signals++
			ufrag = u
			pwd = p
			return nil
		}, func() (frag string, pwd string, err error) {
			return "", "", fmt.Errorf("forced")
		}, "", "", true, 0,
		},

		{"SignalAnswer failed", func(u string, p string) error {
			return fmt.Errorf("forced")
		}, func() (frag string, pwd string, err error) {
			return "ufrag", "pwd", nil
		}, "", "", true, 0,
		},
	}

	for _, table := range tables {
		t.Run(table.name, func(t *testing.T) {

			signals = 0
			ufrag = ""
			pwd = ""

			conn.SetSignalAnswer(table.signalAnswer)
			agent := &iceAgentMock{}
			agent.GetLocalUserCredentialsFunc = table.getLocalUserCredentialsFunc
			conn.agent = agent

			err = conn.sendAnswer()
			if !table.wantError {
				assert.NoError(t, err)
				assert.Equal(t, ufrag, "ufrag")
				assert.Equal(t, pwd, "pwd")
				assert.Equal(t, signals, 1)
			} else {
				assert.Error(t, err)
				assert.Equal(t, signals, 0)
			}

		})
	}
}

func TestConn_reCreateAgent(t *testing.T) {

	conn, err := NewConn(connConf)
	assert.NoError(t, err)

	assert.Nil(t, conn.agent)

	err = conn.reCreateAgent()
	assert.NoError(t, err)

	assert.NotNil(t, conn.agent)
}
