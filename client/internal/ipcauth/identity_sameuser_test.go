package ipcauth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIdentitySameUser(t *testing.T) {
	tests := []struct {
		name string
		a    Identity
		b    Identity
		want bool
	}{
		{
			name: "same uid",
			a:    Identity{UID: 1000, GID: 1000},
			b:    Identity{UID: 1000, GID: 1000},
			want: true,
		},
		{
			name: "same uid, different gid and pid still the same user",
			a:    Identity{UID: 1000, GID: 1000, PID: 11},
			b:    Identity{UID: 1000, GID: 27, PID: 22},
			want: true,
		},
		{
			name: "different uid",
			a:    Identity{UID: 1000},
			b:    Identity{UID: 1001},
			want: false,
		},
		{
			name: "same sid",
			a:    Identity{SID: "S-1-5-21-1-2-3-1001"},
			b:    Identity{SID: "S-1-5-21-1-2-3-1001"},
			want: true,
		},
		{
			name: "same sid, elevation and groups differ",
			a:    Identity{SID: "S-1-5-21-1-2-3-1001", Elevated: true, Groups: []string{sidAdministrators}},
			b:    Identity{SID: "S-1-5-21-1-2-3-1001"},
			want: true,
		},
		{
			name: "different sid",
			a:    Identity{SID: "S-1-5-21-1-2-3-1001"},
			b:    Identity{SID: "S-1-5-21-1-2-3-1002"},
			want: false,
		},
		{
			name: "a windows principal is never a unix one",
			a:    Identity{SID: "S-1-5-18"},
			b:    Identity{UID: 0},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.a.SameUser(tt.b))
			assert.Equal(t, tt.want, tt.b.SameUser(tt.a), "SameUser must be symmetric")
		})
	}
}
