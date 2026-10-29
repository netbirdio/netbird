# NetBird SELinux policy

Confines the NetBird daemon (`netbird_t`) on hosts that run SELinux in enforcing
mode. It ships as the separate `netbird-selinux` package, which depends on
`netbird` and `selinux-policy-targeted`. Without it the daemon runs in
`unconfined_service_t`, as it did before.

## Building

```sh
release_files/selinux/build.sh [output-dir]
```

Needs `selinux-policy-devel`. The release builds it on EL9, the oldest policy the
package targets. The result loads on newer policy, which has been checked on
Fedora 44.

## Installing

Install the package. Its scriptlets load the module, relabel the files it covers
and restart a running daemon. Removing the package unloads the module and
relabels. A manual install can use `semodule -X 200 -i netbird.pp.bz2` followed by
`restorecon -iR` on the paths listed in `post_install.sh` (the binary in `/usr/bin`,
`/usr/sbin` or `/usr/local/bin`, the state, log and config directories, and the daemon,
WireGuard and SSH config files).

## Booleans

| Boolean | Default | Effect |
| --- | --- | --- |
| `netbird_ssh_sessions` | on | The built-in SSH server can start user sessions. Shells and `su` run as `unconfined_t`, since the daemon cannot set the context of the user it switches to, and the daemon gets `sys_admin`, which `setsid -c` needs to hand the terminal to `login`. Turning it off removes the shell, `su` and `sys_admin` rules, but not the `login` transition. |
| `netbird_debug_bundle` | on | Debug bundles can read the journal and list firewall state. |
| `netbird_bind_all_ports` | off | Bind any unreserved TCP port: SSH remote port forwarding and the local metrics endpoint (default `127.0.0.1:9191`). UDP ports are always allowed. |
| `netbird_read_user_home` | off | Read files in user home directories. Needed to add the desktop UI log (`~/.config/netbird/gui-client.log`) to debug bundles. |

Change them with `setsebool -P <name>=on`.

## Diagnosing denials

```sh
journalctl -b | grep 'avc:  denied' | grep netbird
```

To make only the daemon permissive while collecting denials, run
`semanage permissive -a netbird_t`, and remove it with `semanage permissive -d netbird_t`.

## Notes

- Desktop users that run confined need the `netbird_stream_connect` interface to
  reach the daemon socket. Unconfined users need nothing.
- `netbird_ssh_sessions` only gates the shell and `su` transitions. The `login`
  transition is always allowed because its interface cannot sit inside a boolean.
