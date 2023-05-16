package util

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
		encoded := EncodeBase62(tt.num)
		decoded, err := DecodeBase62(encoded)

		if err != nil {
			t.Errorf("Decode error: %v", err)
		}

		if decoded != tt.num {
			t.Errorf("Decode(%v) = %v, want %v", encoded, decoded, tt.num)
		}
	}
}
