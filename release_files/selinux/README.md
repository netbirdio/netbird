# NetBird SELinux policy

Confines the NetBird daemon (`netbird_t`) on hosts that run SELinux in enforcing
mode. It ships as the separate `netbird-selinux` package, which depends on
`netbird` and `selinux-policy-targeted`. The client RPM recommends it, so dnf
installs it along with the client unless weak dependencies are turned off.
Without it the daemon runs in `unconfined_service_t`, as it did before.

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
| `netbird_ssh_sessions` | on | The built-in SSH server can start user sessions. A session starts in the context SELinux assigns the user, the way sshd does it: `login` handles interactive sessions, and the `netbird_ssh_t` helper sets the context for commands of users mapped to a confined SELinux user such as `user_u`. Users mapped to `unconfined_u` run as `unconfined_t`. The daemon gets `sys_admin`, which `setsid -c` needs to hand the terminal to `login`. Turning it off removes the shell, `su`, helper transitions and `sys_admin` rules, but not the `login` transition. |
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
- Sessions of users mapped to a confined SELinux user get the context SELinux assigns
  them, with the role and level of their default login. The `user/role` login syntax of
  sshd is not supported. Users mapped to an administrator SELinux user such as
  `sysadm_u` are refused, as sshd does unless `ssh_sysadm_login` is on.
- Commands of confined users and SFTP are started by the `netbird_ssh_t` helper rather than
  through `su`, so they have no PAM session: no `loginuid` for audit and no logind session.
  Interactive sessions go through `login` and have both.
- When SELinux is permissive, a session whose context cannot be resolved is started anyway
  and a warning is logged. When it is enforcing, the session is refused. Hosts that have
  the SELinux file system but no policy files, such as containers, are left alone.
