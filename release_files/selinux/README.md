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
| `netbird_ssh_sessions` | on | The built-in SSH server can start user sessions. Shells and `su` run as `unconfined_t`, since the daemon cannot set the context of the user it switches to, and the daemon gets `sys_admin`, which `setsid -c` needs to hand the terminal to `login`. Turning it off removes the shell, `su` and `sys_admin` rules, but not the `login` transition. |
| `netbird_debug_bundle` | on | Debug bundles can read the journal and list firewall state. |
| `netbird_bind_all_ports` | off | Bind any unreserved TCP port: SSH remote port forwarding and the local metrics endpoint (default `127.0.0.1:9191`). UDP ports are always allowed. |
| `netbird_read_user_home` | off | Read files in user home directories. Needed to add the desktop UI log (`~/.config/netbird/gui-client.log`) to debug bundles. |

Change them with `setsebool -P <name>=on`.

## Permission map

Every permission the module grants has a reason. This is what needs what, so that a
permission can be retired later without guessing. The evidence is an `avc: granted`
record from the audit module described below, logged during the named scenario on Alma 9.
A permission that no scenario used is listed as such. That says only that the scenarios
that ran did not need it.

Capabilities, as written in `netbird.te`:

| Capability | Needed by | Evidence |
| --- | --- | --- |
| `net_admin` | Interface, address, route, ip rule and firewall changes over netlink, nft and iptables | Every scenario that changes the network |
| `net_raw` | Raw sockets of the loopback WireGuard proxy (`SO_BINDTODEVICE`), ping probes | Daemon start and restart |
| `net_bind_service` | DNS listener on port 53, SSH server on port 22. Granted by `corenet_udp_bind_all_ports` and `corenet_tcp_bind_ssh_port` | Daemon start and restart |
| `sys_ptrace` | Process posture check, which reads `/proc/PID/exe` of other users processes. Processes inside a user namespace stay unreadable (`cap_userns`, denied) | 124 grants in the process check |
| `dac_read_search` | SSH sessions of non-root users, `firewall-cmd` run as the firewalld fallback, the UI log in debug bundles | Each non-root SSH scenario (not `ssh-exec-root`), `firewalld-cli` |
| `dac_override` | TPM access: `/dev/tpmrm0` belongs to `tss` with mode 0660 | Certificate check with a TPM-held key |
| `setuid`, `setgid` | SFTP helper dropping to the session user | The `ssh-sftp` scenarios only |
| `sys_admin` | `setsid -c` before `login` (`netbird_ssh_sessions`). The daemon also probes `su` and `login` at start | Interactive login scenarios, daemon start |
| `audit_write` | Granted by `logging_send_audit_msgs`, not by a rule here | Not seen |
| `kill` | The SSH server signals the process group of a session when it ends (`client/ssh/server/command_execution_unix.go`). A root-owned `su` in the group needs no capability, a process of the user itself would | Not seen |

Left out on purpose: `bpf` and `perfmon` (the client no longer loads eBPF, the WireGuard
proxy is a loopback raw-socket proxy), and `chown`, `fowner`, `fsetid`, `sys_resource`
and `sys_chroot`, which have no code path in the client and were never used in a run.

Everything else, by feature:

| Feature | Grants | Evidence |
| --- | --- | --- |
| Firewall | Transition to `iptables_t` for iptables, ip6tables, nft, ipset and the `*-save` tools, netlink netfilter socket | Every firewall change, debug bundle |
| firewalld | D-Bus to firewalld, and `firewall-cmd` (a `bin_t` python script) as the fallback | `firewalld-dbus`, `firewalld-cli` |
| DNS | Write `net_conf_t` (resolv.conf), bind `dns_port_t`, D-Bus to systemd-resolved and NetworkManager | Daemon start and restart |
| Kernel settings | Read and write `sysctl_net_t` (forwarding, rp_filter, conntrack accounting) | Daemon start, netflow |
| Netflow | Netlink netfilter socket for conntrack events, `nf_conntrack_acct` | `netflow-kernel`: events collected. The userspace filter logged none in the run |
| Netstack | `netbird_wg_runtime_t` and a loopback SOCKS5 listener | `netstack` |
| Posture checks | `getattr` on executables, read `/proc` of other domains, read the certificate store in `netbird_etc_t`, `tpm_device_t` | `posture-process`, `posture-cert-pem`, `posture-cert-tpm` |
| SSH sessions | `su` into `unconfined_t`, `login` into `local_login_t`, ptys (`netbird_devpts_t`, `ptmx_t`), `passwd_file_t`, SSSD and systemd-userdbd lookups, search of `user_home_dir_t` | The `ssh-*` scenarios |
| SSH session teardown | `signal` and `sigkill` on `unconfined_t` | `ssh-session-teardown` |
| Debug bundle | Execute the firewall tools, files in `netbird_tmp_t`, upload over HTTPS. Journal and log reads (`netbird_debug_bundle`) were not used because the bundle took the daemon log file | `bundle-local`, `bundle-upload-put-get` |
| Ports | Bind unreserved TCP and UDP ports, connect to any TCP port | Daemon start, SSH forwarding |

Not exercised yet: the session expiry notice to terminals (`term_write_all_terms` and the
logind session files), lazy connections, exit nodes and routing peers, `netbird expose`,
reading the journal for a debug bundle, and EL8 at runtime.

## Auditing permission use

`audit/netbirdaudit.te` is a second module that adds `auditallow` rules for what
`netbird_t` is granted, so each use is logged as `avc: granted`. Sockets are left out
because they are checked per packet. Use it before retiring a permission, and when a
new feature needs a new one:

```sh
make -C audit -f /usr/share/selinux/devel/Makefile netbirdaudit.pp
semodule -X 300 -i audit/netbirdaudit.pp
semodule -DB      # also log the denials that dontaudit hides
```

Raise `max_log_file` and `num_logs` in `/etc/audit/auditd.conf` and run
`auditctl -b 65536 -r 0` first, since a long run produces tens of thousands of records.
Record a start and an end time around each feature in a marks file, as
`<epoch> S <name>` and `<epoch> E <name>` lines, then map the records to the features:

```sh
python3 audit/report.py <start-epoch> marks > report.tsv
```

Each row is a verdict, class, permission, target type, the commands that used it and the
scenarios it appeared in. A permission that never appears was not needed by what ran.
Remove the audit module afterwards with `semodule -X 300 -r netbirdaudit` and `semodule -B`.

To retire a permission, remove it, rebuild the module and repeat the scenarios that used
it in the report.

## Diagnosing denials

On EL, which runs auditd, denials are in the audit log:

```sh
ausearch -m avc -c netbird
```

On a host without auditd, such as a default Fedora install, they are in the journal:

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
