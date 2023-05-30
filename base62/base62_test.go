package base62

import (
	"testing"
)

func TestEncodeDecode(t *testing.T) {
	tests := []struct {
		num uint32
	}{
		{0},
		{1},
		{42},
		{12345},
		{99999},
		{123456789},
	}

	for _, tt := range tests {
		encoded := Encode(tt.num)
		decoded, err := Decode(encoded)

		if err != nil {
			t.Errorf("Decode error: %v", err)
		}

		if decoded != tt.num {
			t.Errorf("Decode(%v) = %v, want %v", encoded, decoded, tt.num)
		}
	}
}
