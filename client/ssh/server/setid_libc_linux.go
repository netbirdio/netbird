//go:build pkcs11 && linux && !android && (amd64 || arm64)

package server

import (
	"fmt"
	"runtime"
	"sync"
	"syscall"

	"github.com/ebitengine/purego"
)

// This build links libc through purego, whose fakecgo runtime marks the binary as cgo
// without registering the libc hooks a real cgo build provides. syscall's setuid family
// then panics in AllThreadsSyscall, so the calls go to libc directly: glibc applies them
// to every thread, and all Go threads here are created through pthread_create.

type libcSetID struct {
	setgroups     func(size uintptr, list *uint32) int32
	setgid        func(gid uint32) int32
	setuid        func(uid uint32) int32
	setegid       func(egid uint32) int32
	seteuid       func(euid uint32) int32
	errnoLocation func() *int32
}

var (
	libcSetIDOnce sync.Once
	libcSetIDFns  libcSetID
	libcSetIDErr  error
)

func loadLibcSetID() (*libcSetID, error) {
	libcSetIDOnce.Do(func() {
		syms := []struct {
			fn   any
			name string
		}{
			{&libcSetIDFns.setgroups, "setgroups"},
			{&libcSetIDFns.setgid, "setgid"},
			{&libcSetIDFns.setuid, "setuid"},
			{&libcSetIDFns.setegid, "setegid"},
			{&libcSetIDFns.seteuid, "seteuid"},
			{&libcSetIDFns.errnoLocation, "__errno_location"},
		}
		for _, s := range syms {
			addr, err := purego.Dlsym(purego.RTLD_DEFAULT, s.name)
			if err != nil {
				libcSetIDErr = fmt.Errorf("resolve libc %s: %w", s.name, err)
				return
			}
			purego.RegisterFunc(s.fn, addr)
		}
	})
	if libcSetIDErr != nil {
		return nil, libcSetIDErr
	}
	return &libcSetIDFns, nil
}

// libcCall runs call on a locked thread so errno is read from the thread that set it.
func libcCall(call func(*libcSetID) int32) error {
	fns, err := loadLibcSetID()
	if err != nil {
		return err
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if call(fns) == 0 {
		return nil
	}
	if errno := *fns.errnoLocation(); errno != 0 {
		return syscall.Errno(errno)
	}
	return syscall.EINVAL
}

func setgroups(gids []int) error {
	list := make([]uint32, len(gids))
	for i, g := range gids {
		list[i] = uint32(g)
	}
	return libcCall(func(f *libcSetID) int32 {
		if len(list) == 0 {
			return f.setgroups(0, nil)
		}
		return f.setgroups(uintptr(len(list)), &list[0])
	})
}

func setgid(gid int) error {
	return libcCall(func(f *libcSetID) int32 { return f.setgid(uint32(gid)) })
}

func setuid(uid int) error {
	return libcCall(func(f *libcSetID) int32 { return f.setuid(uint32(uid)) })
}

func setegid(egid int) error {
	return libcCall(func(f *libcSetID) int32 { return f.setegid(uint32(egid)) })
}

func seteuid(euid int) error {
	return libcCall(func(f *libcSetID) int32 { return f.seteuid(uint32(euid)) })
}
