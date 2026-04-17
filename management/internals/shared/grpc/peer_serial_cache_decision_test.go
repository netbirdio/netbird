package grpc

import "testing"

func TestShouldSkipNetworkMap(t *testing.T) {
	tests := []struct {
		name          string
		goOS          string
		hit           bool
		cached        peerSyncEntry
		currentSerial uint64
		incomingMeta  uint64
		want          bool
	}{
		{
			name:          "android never skips even on clean cache hit",
			goOS:          "android",
			hit:           true,
			cached:        peerSyncEntry{Serial: 42, MetaHash: 7},
			currentSerial: 42,
			incomingMeta:  7,
			want:          false,
		},
		{
			name:          "android uppercase never skips",
			goOS:          "Android",
			hit:           true,
			cached:        peerSyncEntry{Serial: 42, MetaHash: 7},
			currentSerial: 42,
			incomingMeta:  7,
			want:          false,
		},
		{
			name:          "cache miss forces full path",
			goOS:          "linux",
			hit:           false,
			cached:        peerSyncEntry{},
			currentSerial: 42,
			incomingMeta:  7,
			want:          false,
		},
		{
			name:          "serial mismatch forces full path",
			goOS:          "linux",
			hit:           true,
			cached:        peerSyncEntry{Serial: 41, MetaHash: 7},
			currentSerial: 42,
			incomingMeta:  7,
			want:          false,
		},
		{
			name:          "meta mismatch forces full path",
			goOS:          "linux",
			hit:           true,
			cached:        peerSyncEntry{Serial: 42, MetaHash: 7},
			currentSerial: 42,
			incomingMeta:  9,
			want:          false,
		},
		{
			name:          "clean hit on linux skips",
			goOS:          "linux",
			hit:           true,
			cached:        peerSyncEntry{Serial: 42, MetaHash: 7},
			currentSerial: 42,
			incomingMeta:  7,
			want:          true,
		},
		{
			name:          "clean hit on darwin skips",
			goOS:          "darwin",
			hit:           true,
			cached:        peerSyncEntry{Serial: 42, MetaHash: 7},
			currentSerial: 42,
			incomingMeta:  7,
			want:          true,
		},
		{
			name:          "clean hit on windows skips",
			goOS:          "windows",
			hit:           true,
			cached:        peerSyncEntry{Serial: 42, MetaHash: 7},
			currentSerial: 42,
			incomingMeta:  7,
			want:          true,
		},
		{
			name:          "zero current serial never skips",
			goOS:          "linux",
			hit:           true,
			cached:        peerSyncEntry{Serial: 0, MetaHash: 7},
			currentSerial: 0,
			incomingMeta:  7,
			want:          false,
		},
		{
			name:          "empty goos treated as non-android and skips",
			goOS:          "",
			hit:           true,
			cached:        peerSyncEntry{Serial: 42, MetaHash: 7},
			currentSerial: 42,
			incomingMeta:  7,
			want:          true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := shouldSkipNetworkMap(tc.goOS, tc.hit, tc.cached, tc.currentSerial, tc.incomingMeta)
			if got != tc.want {
				t.Fatalf("shouldSkipNetworkMap(%q, hit=%v, cached=%+v, current=%d, meta=%d) = %v, want %v",
					tc.goOS, tc.hit, tc.cached, tc.currentSerial, tc.incomingMeta, got, tc.want)
			}
		})
	}
}
