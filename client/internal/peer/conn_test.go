package peer

import (
	"github.com/pion/ice/v2"
	"github.com/stretchr/testify/assert"
	"github.com/wiretrustee/wiretrustee/client/internal/proxy"
	"sync"
	"testing"
	"time"
)

var connConf = ConnConfig{
	Key:                "LLHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU=",
	LocalKey:           "RRHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU=",
	StunTurn:           []*ice.URL{},
	InterfaceBlackList: nil,
	Timeout:            time.Second,
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
	signalOffer := func(u string, p string) error {
		signals++
		ufrag = u
		pwd = p
		return nil
	}

	agent := &iceAgentMock{}
	agent.GetLocalUserCredentialsFunc = func() (frag string, pwd string, err error) {
		return "ufrag", "pwd", nil
	}
	conn.agent = agent

	conn.SetSignalOffer(signalOffer)

	err = conn.sendOffer()
	assert.NoError(t, err)
	assert.Equal(t, ufrag, "ufrag")
	assert.Equal(t, pwd, "pwd")
}

func TestConn_reCreateAgent(t *testing.T) {

	conn, err := NewConn(connConf)
	assert.NoError(t, err)

	assert.Nil(t, conn.agent)

	err = conn.reCreateAgent()
	assert.NoError(t, err)

	assert.NotNil(t, conn.agent)
}
