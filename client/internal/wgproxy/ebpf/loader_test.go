//go:build linux

package ebpf

import (
	"testing"
)

func Test_newEBPF(t *testing.T) {
	ebpf := NewEBPF()
	err := ebpf.Load(1234, 51892)
	defer func() {
		_ = ebpf.Free()
	}()
	if err != nil {
		t.Errorf("%s", err)
	}
}
