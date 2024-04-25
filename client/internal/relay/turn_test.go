package relay

import (
	"os"
	"sync"
	"testing"

	"github.com/pion/stun/v2"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/util"
)

const (
	userName = "1714092678"
	password = "8PEprGKo+UARpYpQOulNz3H24dI="
)

func TestMain(m *testing.M) {
	_ = util.InitLog("trace", "console")
	code := m.Run()
	os.Exit(code)
}

func TestMyTurnUpload(t *testing.T) {
	turnURI, err := stun.ParseURI("turn:api.stage.netbird.io:3478?transport=udp")
	if err != nil {
		t.Fatalf("failed to parse stun url: %v", err)
	}
	turnURI.Username = userName
	turnURI.Password = password

	stunURI, err := stun.ParseURI("stun:api.stage.netbird.io:3478")
	if err != nil {
		t.Fatalf("failed to parse stun url: %v", err)
	}
	turnRelayA := NewPermanentTurn(stunURI, turnURI)
	err = turnRelayA.Open()
	if err != nil {
		t.Fatalf("failed to open turn relay: %v", err)
	}
	defer turnRelayA.Close()

	turnRelayB := NewPermanentTurn(stunURI, turnURI)
	peerBAddr, err := turnRelayB.discoverPublicIPByStun()
	if err != nil {
		t.Fatalf("failed to discover public ip: %v", err)
	}

	err = turnRelayA.PunchHole(peerBAddr)
	if err != nil {
		t.Fatalf("failed to punch hole: %v", err)
	}

	// at this point, the relayed side should be established

	wg := sync.WaitGroup{}
	wg.Add(2)

	speedB := NewSpeed()
	go func() {
		err := speedB.ReceiveFileFromAddr(turnRelayA.relayConn.LocalAddr())
		if err != nil {
			log.Errorf("failed to receive file: %v", err)
		}
		wg.Done()
	}()

	speedA := NewSpeed()
	go func() {
		err := speedA.SendFileToPC(turnRelayA.relayConn)
		if err != nil {
			log.Errorf("failed to send file: %v", err)
		}
		log.Debugf("file sent")
		wg.Done()
	}()

	wg.Wait()
}

func TestMyTurnDownload(t *testing.T) {
	turnURI, err := stun.ParseURI("turn:api.stage.netbird.io:3478?transport=udp")
	if err != nil {
		t.Fatalf("failed to parse stun url: %v", err)
	}
	turnURI.Username = "1714016034"
	turnURI.Password = "oDpL6tDu0d+xcO3rQnHoEvbcS/Q="

	stunURI, err := stun.ParseURI("stun:api.stage.netbird.io:3478")
	if err != nil {
		t.Fatalf("failed to parse stun url: %v", err)
	}
	turnRelayA := NewPermanentTurn(stunURI, turnURI)
	err = turnRelayA.Open()
	if err != nil {
		t.Fatalf("failed to open turn relay: %v", err)
	}
	defer turnRelayA.Close()

	turnRelayB := NewPermanentTurn(stunURI, turnURI)
	peerBAddr, err := turnRelayB.discoverPublicIPByStun()
	if err != nil {
		t.Fatalf("failed to discover public ip: %v", err)
	}

	err = turnRelayA.PunchHole(peerBAddr)
	if err != nil {
		t.Fatalf("failed to punch hole: %v", err)
	}

	// at this point, the relayed side should be established

	wg := sync.WaitGroup{}
	wg.Add(2)

	speedB := NewSpeed()
	go func() {
		err := speedB.SendFileToAddr(turnRelayA.relayConn.LocalAddr())
		if err != nil {
			log.Errorf("failed to receive file: %v", err)
		}
		wg.Done()
	}()

	speedA := NewSpeed()
	go func() {
		err := speedA.ReceiveFileFromPC(turnRelayA.relayConn)
		if err != nil {
			log.Errorf("failed to send file: %v", err)
		}
		log.Debugf("file sent")
		wg.Done()
	}()

	wg.Wait()
}
