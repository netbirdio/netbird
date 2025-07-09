//go:build android

package android

import (
	"fmt"
	_ "unsafe"
)

// https://github.com/golang/go/pull/69543/commits/aad6b3b32c81795f86bc4a9e81aad94899daf520
// In Android version 11 and earlier, pidfd-related system calls
// are not allowed by the seccomp policy, which causes crashes due
// to SIGSYS signals.

//go:linkname checkPidfdOnce os.checkPidfdOnce
var checkPidfdOnce func() error

func execWorkaround(androidSDKVersion int) {
	if androidSDKVersion > 30 { // above Android 11
		return
	}

	checkPidfdOnce = func() error {
		return fmt.Errorf("unsupported Android version")
	}
}
