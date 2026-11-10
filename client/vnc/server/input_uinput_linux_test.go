//go:build linux

package server

import (
	"sort"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
)

// The kernel rejects a write whose length is not exactly sizeof(struct
// input_event), so the mirror has to track the platform's timeval: 24 bytes
// where a C long is 8, 16 where it is 4.
func TestInputEventMatchesKernelABI(t *testing.T) {
	const longSize = unsafe.Sizeof(uintptr(0))
	want := uintptr(2)*longSize + 2 + 2 + 4
	// The struct is aligned to its widest field, which is the long.
	if pad := want % longSize; pad != 0 {
		want += longSize - pad
	}
	if got := unsafe.Sizeof(inputEvent{}); got != want {
		t.Fatalf("sizeof(inputEvent) = %d, want %d for a %d-byte long", got, want, longSize)
	}
}

// uinput only delivers key events whose code was advertised with UI_SET_KEYBIT
// at device-creation time. Anything qemuToLinuxKey can produce therefore has to
// appear in buildUInputKeymap, or the kernel silently drops those keys.
func TestUInputKeymapAdvertisesEveryMappedScancode(t *testing.T) {
	advertised := make(map[uint16]struct{})
	for _, code := range buildUInputKeymap() {
		advertised[code] = struct{}{}
	}

	var missing []int
	for _, code := range qemuToLinuxKey {
		if code == 0 {
			continue
		}
		if _, ok := advertised[uint16(code)]; !ok {
			missing = append(missing, code)
		}
	}
	sort.Ints(missing)
	assert.Empty(t, missing, "KEY_ codes reachable through qemuToLinuxKey but never advertised to uinput")
}
