package networkmonitor

import "golang.org/x/sys/unix"

func monitorScopedFlag() int { return unix.RTF_IFSCOPE }
