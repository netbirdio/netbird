package relay

import (
	"os"
	"testing"

	"github.com/pion/stun/v2"

	"github.com/netbirdio/netbird/util"
)

func TestMain(m *testing.M) {
	_ = util.InitLog("trace", "console")
	code := m.Run()
	os.Exit(code)
}

func TestNewPermanentTurn(t *testing.T) {
	turnURI, err := stun.ParseURI("turns:turn.netbird.io:443?transport=tcp")
	if err != nil {
		t.Errorf("failed to parse stun url: %v", err)
	}
	turnURI.Username = "1713006060"
	turnURI.Password = "pO5Pfx15luZ92mW+FHPa6/LtJ7Y="

	stunURI, err := stun.ParseURI("stun:stun.netbird.io:5555")
	if err != nil {
		t.Errorf("failed to parse stun url: %v", err)
	}
	turnRelay := NewPermanentTurn(stunURI, turnURI)
	err = turnRelay.Open()
	if err != nil {
		t.Errorf("failed to open turn relay: %v", err)
	}

}
