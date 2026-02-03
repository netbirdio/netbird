package base62

import (
	"errors"
	"math"
	"testing"
)

func TestEncodeDecode(t *testing.T) {
	testCases := []struct {
		input    uint32
		expected string
	}{
		{0, "0"},
		{1, "1"},
		{5, "5"},
		{9, "9"},
		{10, "A"},
		{42, "g"},
		{61, "z"},
		{62, "10"},
		{'0', "m"},
		{'9', "v"},
		{'A', "13"},
		{'Z', "1S"},
		{'a', "1Z"},
		{'z', "1y"},
		{99999, "Q0t"},
		{12345, "3D7"},
		{123456789, "8M0kX"},
		{math.MaxUint32, "4gfFC3"},
	}

	for _, tc := range testCases {
		encoded := Encode(tc.input)
		if encoded != tc.expected {
			t.Errorf("Encode(%d) = %s; want %s", tc.input, encoded, tc.expected)
		}
		decoded, err := Decode(encoded)
		if err != nil {
			t.Errorf("Expected error nil, got %v", err)
		}

		if decoded != tc.input {
			t.Errorf("Decode(%v) = %v, want %v", encoded, decoded, tc.input)
		}
	}
}

// Decode handles empty string input with appropriate error
func TestDecodeEmptyString(t *testing.T) {
	if _, err := Decode(""); !errors.Is(err, ErrEmptyString) {
		t.Errorf("Expected error %v, got %v", ErrEmptyString, err)
	}
}

func TestDecodeOverflow(t *testing.T) {
	if _, err := Decode("4gfFC4"); !errors.Is(err, ErrOverflow) {
		t.Errorf("Expected error %v, got %v", ErrOverflow, err)
	}
}

func TestDecodeInvalid(t *testing.T) {
	if _, err := Decode("/"); !errors.Is(err, ErrInvalidChar) {
		t.Errorf("Expected error %v, got %v", ErrInvalidChar, err)
	}
}
