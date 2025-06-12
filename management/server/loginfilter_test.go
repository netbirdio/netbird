package server

import (
	"fmt"
	"hash/fnv"
	"testing"

	"github.com/netbirdio/netbird/management/server/peer"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
)

func BenchmarkMetaHash(b *testing.B) {
	meta := peer.PeerSystemMeta{
		WtVersion:     "1.0.0",
		OSVersion:     "Linux 5.4.0",
		KernelVersion: "5.4.0-42-generic",
		Hostname:      "test-host",
	}
	b.Run("fnv", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			metaHashFnv(meta)
		}
	})
	b.Run("builder", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			metaHash(meta)
		}
	})
	b.Run("strings", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			metaHashStrings(meta)
		}
	})
}

func metaHashStrings(meta nbpeer.PeerSystemMeta) string {
	return meta.WtVersion + meta.OSVersion + meta.KernelVersion + meta.Hostname
}

func metaHashFnv(meta nbpeer.PeerSystemMeta) string {
	h := fnv.New64a()
	h.Write([]byte(meta.WtVersion))
	h.Write([]byte(meta.OSVersion))
	h.Write([]byte(meta.KernelVersion))
	h.Write([]byte(meta.Hostname))
	return fmt.Sprintf("%x", h.Sum64())
}
