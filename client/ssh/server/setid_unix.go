//go:build unix && !(pkcs11 && linux && !android && (amd64 || arm64))

package server

import "syscall"

func setgroups(gids []int) error {
	return syscall.Setgroups(gids)
}

func setgid(gid int) error {
	return syscall.Setgid(gid)
}

func setuid(uid int) error {
	return syscall.Setuid(uid)
}

func setegid(egid int) error {
	return syscall.Setegid(egid)
}

func seteuid(euid int) error {
	return syscall.Seteuid(euid)
}
