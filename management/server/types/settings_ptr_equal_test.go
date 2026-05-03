package types

import "testing"

// Codex review: account.go:332 updateAccountPeers used to silently
// miss ConnectionMode + timeout-field changes. The fix relies on
// these nil-safe equality helpers — make sure they cover the cases.
func TestStringPtrEqual(t *testing.T) {
	a := "p2p-dynamic"
	b := "p2p-dynamic"
	c := "p2p-lazy"
	tests := []struct {
		name string
		x    *string
		y    *string
		want bool
	}{
		{"both_nil", nil, nil, true},
		{"first_nil", nil, &a, false},
		{"second_nil", &a, nil, false},
		{"same_value", &a, &b, true},
		{"different_value", &a, &c, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := StringPtrEqual(tc.x, tc.y); got != tc.want {
				t.Errorf("StringPtrEqual(%v, %v) = %v, want %v", deref(tc.x), deref(tc.y), got, tc.want)
			}
		})
	}
}

func TestUint32PtrEqual(t *testing.T) {
	a := uint32(86400)
	b := uint32(86400)
	c := uint32(300)
	tests := []struct {
		name string
		x    *uint32
		y    *uint32
		want bool
	}{
		{"both_nil", nil, nil, true},
		{"first_nil", nil, &a, false},
		{"second_nil", &a, nil, false},
		{"same_value", &a, &b, true},
		{"different_value", &a, &c, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Uint32PtrEqual(tc.x, tc.y); got != tc.want {
				t.Errorf("Uint32PtrEqual(%v, %v) = %v, want %v", derefU(tc.x), derefU(tc.y), got, tc.want)
			}
		})
	}
}

// Real-world scenario lifted from the bug Codex caught: dashboard
// switches an account from p2p-lazy to p2p-dynamic while leaving
// every other setting alone. Settings.Copy must produce a new object
// that compares unequal on ConnectionMode (the trigger for the
// updateAccountPeers push) and equal on everything else.
func TestSettings_PushTriggerOnConnectionModeFlip(t *testing.T) {
	lazy := "p2p-lazy"
	dynamic := "p2p-dynamic"
	relayTO := uint32(86400)
	old := &Settings{
		ConnectionMode:      &lazy,
		RelayTimeoutSeconds: &relayTO,
	}
	new := old.Copy()
	new.ConnectionMode = &dynamic
	if StringPtrEqual(old.ConnectionMode, new.ConnectionMode) {
		t.Fatal("ConnectionMode flip must NOT be equal (otherwise updateAccountPeers won't fire)")
	}
	if !Uint32PtrEqual(old.RelayTimeoutSeconds, new.RelayTimeoutSeconds) {
		t.Fatal("RelayTimeoutSeconds unchanged must remain equal across Copy()")
	}
}

func deref(p *string) string {
	if p == nil {
		return "<nil>"
	}
	return *p
}
func derefU(p *uint32) any {
	if p == nil {
		return "<nil>"
	}
	return *p
}
