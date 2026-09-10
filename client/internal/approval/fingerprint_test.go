package approval

import "testing"

// TestShortKeyFingerprint locks in the format the VNC approval prompt
// shows to the user. The fingerprint is the user's only cryptographic
// anchor against a malicious management server that pushes a spoofed
// display name, so accidental changes to its format would silently
// undermine that defence.
func TestShortKeyFingerprint(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "full_32_byte_pubkey",
			in:   "0123456789abcdeffedcba9876543210ffeeddccbbaa99887766554433221100",
			want: "0123-4567-89ab-cdef",
		},
		{
			name: "exactly_16_chars",
			in:   "0123456789abcdef",
			want: "0123-4567-89ab-cdef",
		},
		{
			name: "borderline_8_chars",
			in:   "01234567",
			want: "0123-4567",
		},
		{
			name: "too_short_returns_empty",
			in:   "0123",
			want: "",
		},
		{
			name: "empty_returns_empty",
			in:   "",
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ShortKeyFingerprint(tc.in)
			if got != tc.want {
				t.Fatalf("ShortKeyFingerprint(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestShortKeyFingerprint_DistinctKeysDistinctOutputs guards against a
// formatting bug that would collapse different prefixes onto the same
// displayed fingerprint and let an attacker substitute their pubkey for
// a victim's while keeping the prompt visually identical.
func TestShortKeyFingerprint_DistinctKeysDistinctOutputs(t *testing.T) {
	a := ShortKeyFingerprint("0123456789abcdef" + "rest_of_pubkey_ignored")
	b := ShortKeyFingerprint("0123456789abcde0" + "rest_of_pubkey_ignored")
	if a == b {
		t.Fatalf("expected distinct outputs for distinct prefixes, both = %q", a)
	}
}
