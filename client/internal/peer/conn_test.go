package peer

import (
	"github.com/pion/ice/v2"
	"github.com/wiretrustee/wiretrustee/client/internal/proxy"
	"sync"
	"testing"
	"time"
)

func TestConn_GetKey(t *testing.T) {

	conf := ConnConfig{
		Key:                "LLHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU=",
		LocalKey:           "RRHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU=",
		StunTurn:           []*ice.URL{},
		InterfaceBlackList: nil,
		Timeout:            time.Second,
		ProxyConfig:        proxy.Config{},
	}

	conn, err := NewConn(conf)
	if err != nil {
		return
	}

	got := conn.GetKey()

	if got != conf.Key {
		t.Errorf("expecting %s key returned, got %s", conf.Key, got)
	}

}

func TestConn_OnRemoteOffer(t *testing.T) {
	conf := ConnConfig{
		Key:                "LLHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU=",
		LocalKey:           "RRHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU=",
		StunTurn:           []*ice.URL{},
		InterfaceBlackList: nil,
		Timeout:            time.Second,
		ProxyConfig:        proxy.Config{},
	}

	conn, err := NewConn(conf)
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
	conf := ConnConfig{
		Key:                "LLHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU=",
		LocalKey:           "RRHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU=",
		StunTurn:           []*ice.URL{},
		InterfaceBlackList: nil,
		Timeout:            time.Second,
		ProxyConfig:        proxy.Config{},
	}

	conn, err := NewConn(conf)
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
