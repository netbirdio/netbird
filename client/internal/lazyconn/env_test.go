package lazyconn

import (
	"os"
	"testing"
)

func TestEnvState(t *testing.T) {
	tests := []struct {
		value string
		set   bool
		want  State
	}{
		{set: false, want: StateUnset},
		{value: "", set: true, want: StateUnset},
		{value: "on", set: true, want: StateOn},
		{value: "ON", set: true, want: StateOn},
		{value: "true", set: true, want: StateOn},
		{value: "1", set: true, want: StateOn},
		{value: " on ", set: true, want: StateOn},
		{value: "off", set: true, want: StateOff},
		{value: "OFF", set: true, want: StateOff},
		{value: "false", set: true, want: StateOff},
		{value: "0", set: true, want: StateOff},
		{value: "auto", set: true, want: StateUnset},
		{value: "garbage", set: true, want: StateUnset},
	}

	for _, tt := range tests {
		name := tt.value
		if !tt.set {
			name = "unset"
		}
		t.Run(name, func(t *testing.T) {
			t.Setenv(EnvLazyConn, tt.value)
			if !tt.set {
				os.Unsetenv(EnvLazyConn)
			}

			if got := EnvState(); got != tt.want {
				t.Fatalf("EnvState() = %v, want %v", got, tt.want)
			}
		})
	}
}
