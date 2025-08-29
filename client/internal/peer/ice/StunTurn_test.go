package ice

import (
	"testing"
)

func TestStunTurn_LoadEmpty(t *testing.T) {
	var stStunTurn StunTurn
	got := stStunTurn.Load()
	if len(got) != 0 {
		t.Errorf("StunTurn.Load() = %v, want %v", got, nil)
	}
}
