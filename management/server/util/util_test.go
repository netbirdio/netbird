package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestElementsMatch(t *testing.T) {
	tests := []struct {
		name string
		a, b []string
		want bool
	}{
		{"both nil", nil, nil, true},
		{"nil and empty", nil, []string{}, true},
		{"same order", []string{"a", "b"}, []string{"a", "b"}, true},
		{"different order", []string{"a", "b", "c"}, []string{"c", "a", "b"}, true},
		{"different length", []string{"a"}, []string{"a", "b"}, false},
		{"different element", []string{"a", "b"}, []string{"a", "c"}, false},
		{"different multiplicity", []string{"a", "a", "b"}, []string{"a", "b", "b"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ElementsMatch(tt.a, tt.b), "ElementsMatch(%v, %v)", tt.a, tt.b)
		})
	}
}
