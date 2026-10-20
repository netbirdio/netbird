package auth

import (
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestIsPeerLoginExpired(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "nil",
			err:  nil,
			want: false,
		},
		{
			name: "plain error (not a gRPC status)",
			err:  errors.New("network read: connection reset"),
			want: false,
		},
		{
			name: "PermissionDenied with different message",
			err:  status.Error(codes.PermissionDenied, "user is blocked"),
			want: false,
		},
		{
			name: "Unauthenticated with the expected phrase",
			// Wrong status code — must still return false.
			err:  status.Error(codes.Unauthenticated, "peer login has expired, please log in once more"),
			want: false,
		},
		{
			name: "exact server message",
			err:  status.Error(codes.PermissionDenied, "peer login has expired, please log in once more"),
			want: true,
		},
		{
			name: "phrase as substring",
			// Future-proofing: if mgm reworords but keeps the phrase,
			// the friendly fallback must still kick in.
			err:  status.Error(codes.PermissionDenied, "session refused: peer login has expired (account=foo)"),
			want: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isPeerLoginExpired(tc.err); got != tc.want {
				t.Fatalf("isPeerLoginExpired(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestErrSetupKeyOnSSOExpiredPeer(t *testing.T) {
	// Sentinel must surface as PermissionDenied so the upstream
	// isPermissionDenied / isAuthError checks classify it correctly
	// (short-circuit retry backoff, set StatusNeedsLogin).
	if !isPermissionDenied(errSetupKeyOnSSOExpiredPeer) {
		t.Fatalf("errSetupKeyOnSSOExpiredPeer must be a PermissionDenied gRPC error")
	}

	// Message must actually mention SSO and `netbird up` so it is
	// actionable for the end user. Loose substring checks keep the
	// test resilient to copy edits.
	s, _ := status.FromError(errSetupKeyOnSSOExpiredPeer)
	msg := strings.ToLower(s.Message())
	for _, want := range []string{"sso", "netbird up"} {
		if !strings.Contains(msg, want) {
			t.Errorf("sentinel message should contain %q, got %q", want, s.Message())
		}
	}
}
