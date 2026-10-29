// Package getent resolves users and groups through the host's NSS stack.
// Built without cgo, os/user reads /etc/passwd and /etc/group alone and misses
// anything LDAP, SSSD or winbind provide; the getent and id commands resolve
// through NSS whatever the build. The lookups here try the standard library
// first, which needs no subprocess, and fall back to those commands.
package getent
