package manager

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAllowUnfilteredIPv6(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{name: "unset keeps the deny", value: "", want: false},
		{name: "true", value: "true", want: true},
		{name: "one", value: "1", want: true},
		{name: "false", value: "false", want: false},
		{name: "zero", value: "0", want: false},
		{name: "not a boolean keeps the deny", value: "yes please", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(EnvAllowUnfilteredIPv6, tt.value)
			assert.Equal(t, tt.want, AllowUnfilteredIPv6())
		})
	}
}
