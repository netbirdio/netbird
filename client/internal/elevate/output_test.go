package elevate

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFirstLine(t *testing.T) {
	tests := []struct{ in, want string }{
		{in: "", want: noOutput},
		{in: "  \n ", want: noOutput},
		{in: "one line", want: "one line"},
		{in: "first\nsecond", want: "first"},
		{in: "\nsecond\n", want: "second"},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.want, firstLine(tt.in), "input %q", tt.in)
	}
}
