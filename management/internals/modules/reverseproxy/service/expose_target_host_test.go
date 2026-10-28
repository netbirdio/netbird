package service

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeExposeTargetHost(t *testing.T) {
	longLabel := strings.Repeat("a", 64)
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr string
	}{
		{name: "hostname", in: "other-service", want: "other-service"},
		{name: "uppercase hostname", in: "Other-Service", want: "other-service"},
		{name: "ipv4", in: "10.0.0.29", want: "10.0.0.29"},
		{name: "ipv4 trailing dot", in: "10.0.0.29.", want: "10.0.0.29"},
		{name: "ipv6", in: "2001:db8::1", want: "2001:db8::1"},
		{name: "ipv6 brackets", in: "[2001:db8::1]", want: "2001:db8::1"},
		{name: "fqdn trailing dot", in: "db.internal.", want: "db.internal"},
		{name: "empty", in: "", wantErr: "empty"},
		{name: "scheme", in: "http://other-service", wantErr: "scheme"},
		{name: "port", in: "other-service:8080", wantErr: "port"},
		{name: "path", in: "other-service/app", wantErr: "path"},
		{name: "loopback ipv4", in: "127.0.0.1", wantErr: "loopback"},
		{name: "loopback ipv4 trailing dot", in: "127.0.0.1.", wantErr: "loopback"},
		{name: "loopback ipv6", in: "[::1]", wantErr: "loopback"},
		{name: "localhost", in: "localhost", wantErr: "loopback"},
		{name: "localhost trailing dot", in: "localhost.", wantErr: "loopback"},
		{name: "localhost uppercase", in: "LOCALHOST", wantErr: "loopback"},
		{name: "localhost subdomain", in: "foo.localhost", wantErr: "loopback"},
		{name: "localhost subdomain trailing dot", in: "foo.localhost.", wantErr: "loopback"},
		{name: "mapped loopback", in: "::ffff:127.0.0.1", wantErr: "loopback"},
		{name: "colon hostname", in: "foo:bar:baz", wantErr: "not a valid hostname"},
		{name: "unbalanced open bracket", in: "[2001:db8::1", wantErr: "unbalanced brackets"},
		{name: "unbalanced close bracket", in: "2001:db8::1]", wantErr: "unbalanced brackets"},
		{name: "brackets around hostname", in: "[other-service]", wantErr: "not a valid hostname"},
		{name: "empty brackets", in: "[]", wantErr: "unbalanced brackets"},
		{name: "underscore", in: "other_service", wantErr: "not a valid hostname"},
		{name: "numeric only", in: "123", wantErr: "not a valid hostname"},
		{name: "numeric labels", in: "1.2.3", wantErr: "not a valid hostname"},
		{name: "too long label", in: longLabel, wantErr: "not a valid hostname"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeExposeTargetHost(tt.in)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
