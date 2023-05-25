package wgproxy

import (
	"testing"
)

func Test_newEBPF(t *testing.T) {
	ebpf := newEBPF()
	err := ebpf.load(1234, 51892)
	defer ebpf.free()
	if err != nil {
		t.Errorf("%s", err)
	}
}
