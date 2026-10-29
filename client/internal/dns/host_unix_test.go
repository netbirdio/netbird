//go:build (linux && !android) || freebsd

package dns

import "testing"

func TestParseNsswitchResolveAhead(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{
			name: "resolve before dns with action token",
			in:   "hosts: mymachines resolve [!UNAVAIL=return] files myhostname dns\n",
			want: true,
		},
		{
			name: "dns before resolve",
			in:   "hosts: files mdns4_minimal [NOTFOUND=return] dns resolve\n",
			want: false,
		},
		{
			name: "debian default with only dns",
			in:   "hosts: files mdns4_minimal [NOTFOUND=return] dns mymachines\n",
			want: false,
		},
		{
			name: "neither resolve nor dns",
			in:   "hosts: files myhostname\n",
			want: false,
		},
		{
			name: "no hosts line",
			in:   "passwd: files systemd\ngroup: files systemd\n",
			want: false,
		},
		{
			name: "empty",
			in:   "",
			want: false,
		},
		{
			name: "comments and blank lines ignored",
			in:   "# comment\n\n# another\nhosts: resolve dns\n",
			want: true,
		},
		{
			name: "trailing inline comment",
			in:   "hosts: resolve [!UNAVAIL=return] dns # fallback\n",
			want: true,
		},
		{
			name: "hosts token must be the first field",
			in:   "  hosts: resolve dns\n",
			want: true,
		},
		{
			name: "other db line mentioning resolve is ignored",
			in:   "networks: resolve\nhosts: dns\n",
			want: false,
		},
		{
			name: "only resolve, no dns",
			in:   "hosts: files resolve\n",
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseNsswitchResolveAhead([]byte(tt.in)); got != tt.want {
				t.Errorf("parseNsswitchResolveAhead() = %v, want %v", got, tt.want)
			}
		})
	}
}
