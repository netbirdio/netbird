package connectionmode

import (
	"testing"

	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

func TestParseString(t *testing.T) {
	cases := []struct {
		input   string
		want    Mode
		wantErr bool
	}{
		{"relay-forced", ModeRelayForced, false},
		{"p2p", ModeP2P, false},
		{"p2p-lazy", ModeP2PLazy, false},
		{"p2p-dynamic", ModeP2PDynamic, false},
		{"follow-server", ModeFollowServer, false},
		{"", ModeUnspecified, false},
		{"P2P", ModeP2P, false},
		{"  p2p-lazy  ", ModeP2PLazy, false},
		{"junk", ModeUnspecified, true},
	}
	for _, c := range cases {
		got, err := ParseString(c.input)
		if (err != nil) != c.wantErr {
			t.Errorf("ParseString(%q): err=%v wantErr=%v", c.input, err, c.wantErr)
			continue
		}
		if got != c.want {
			t.Errorf("ParseString(%q) = %v, want %v", c.input, got, c.want)
		}
	}
}

func TestFromProto(t *testing.T) {
	cases := []struct {
		input mgmProto.ConnectionMode
		want  Mode
	}{
		{mgmProto.ConnectionMode_CONNECTION_MODE_UNSPECIFIED, ModeUnspecified},
		{mgmProto.ConnectionMode_CONNECTION_MODE_RELAY_FORCED, ModeRelayForced},
		{mgmProto.ConnectionMode_CONNECTION_MODE_P2P, ModeP2P},
		{mgmProto.ConnectionMode_CONNECTION_MODE_P2P_LAZY, ModeP2PLazy},
		{mgmProto.ConnectionMode_CONNECTION_MODE_P2P_DYNAMIC, ModeP2PDynamic},
	}
	for _, c := range cases {
		got := FromProto(c.input)
		if got != c.want {
			t.Errorf("FromProto(%v) = %v, want %v", c.input, got, c.want)
		}
	}
}

func TestToProto(t *testing.T) {
	for _, m := range []Mode{ModeUnspecified, ModeRelayForced, ModeP2P, ModeP2PLazy, ModeP2PDynamic} {
		got := FromProto(m.ToProto())
		if got != m {
			t.Errorf("round-trip Mode %v -> proto -> Mode = %v", m, got)
		}
	}
	if got := ModeFollowServer.ToProto(); got != mgmProto.ConnectionMode_CONNECTION_MODE_UNSPECIFIED {
		t.Errorf("ModeFollowServer.ToProto() = %v, want UNSPECIFIED", got)
	}
}

func TestResolveLegacyLazyBool(t *testing.T) {
	if got := ResolveLegacyLazyBool(true); got != ModeP2PLazy {
		t.Errorf("ResolveLegacyLazyBool(true) = %v, want ModeP2PLazy", got)
	}
	if got := ResolveLegacyLazyBool(false); got != ModeP2P {
		t.Errorf("ResolveLegacyLazyBool(false) = %v, want ModeP2P", got)
	}
}

func TestToLazyConnectionEnabled(t *testing.T) {
	cases := []struct {
		mode Mode
		want bool
	}{
		{ModeRelayForced, false},
		{ModeP2P, false},
		{ModeP2PLazy, true},
		{ModeP2PDynamic, false},
		{ModeUnspecified, false},
	}
	for _, c := range cases {
		got := c.mode.ToLazyConnectionEnabled()
		if got != c.want {
			t.Errorf("Mode %v ToLazyConnectionEnabled() = %v, want %v", c.mode, got, c.want)
		}
	}
}

func TestStringRoundTrip(t *testing.T) {
	for _, m := range []Mode{ModeRelayForced, ModeP2P, ModeP2PLazy, ModeP2PDynamic, ModeFollowServer} {
		got, err := ParseString(m.String())
		if err != nil {
			t.Errorf("round-trip parse of %v.String() failed: %v", m, err)
		}
		if got != m {
			t.Errorf("round-trip %v -> %q -> %v", m, m.String(), got)
		}
	}
}
