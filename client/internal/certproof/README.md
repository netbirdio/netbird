# Certificate posture proofs

A peer answers a management certificate challenge by signing the challenge nonce with a
private key it holds, and sending back the certificate chain. Management verifies the
chain against the CAs configured on the check and verifies the signature, which proves
the peer holds the key rather than merely a copy of the certificate.

The signature covers `netbird-posture-cert-v1 || nonce || peerKey`, so a proof is bound
to one WireGuard peer key and cannot be replayed by another peer.

## Where certificates come from

| Platform | Store | Read by |
| --- | --- | --- |
| macOS | System keychain | the daemon, directly |
| macOS | console user's login keychain | a helper in that user's desktop session |
| Windows | `LocalMachine\MY` | the service, directly |
| Windows | signed-in user's `CurrentUser\MY` | a helper launched with that session's token |
| Linux and others | PEM directory, `NB_CERT_STORE_DIR` or `/etc/netbird/certs` | the daemon, directly |

macOS and Windows both keep per-user certificates out of reach of a privileged daemon,
and both are handled the same way: the daemon reads the machine store itself and
launches `netbird posture cert-proof` as the signed-in user for the rest. Only the
signature and the chain come back. The helper, the request and response types and the
subcommand are shared; only the way the child is launched differs.

## macOS: why the daemon cannot read a login keychain

The daemon runs as root from a LaunchDaemon. Its keychain search list is the System
keychain, which is where MDM installs device identities, and nothing else. A user's
login keychain is out of reach for reasons that are not about privilege:

- `login.keychain-db` is unlocked by `securityd` **in the user's session**. The daemon
  lives in a different Mach bootstrap namespace, so from where it stands the keychain is
  locked no matter which uid it runs as.
- Every private key carries an ACL naming the applications allowed to use it. A process
  that is not listed causes a consent prompt *in the user's session*. A daemon has no
  session to show one in, so it receives `errSecInteractionNotAllowed (-25308)` instead.

Dropping to the user's uid with `SysProcAttr.Credential` does **not** fix this: uid is
not what selects the securityd instance, the bootstrap namespace is. The process has to
enter the user's session, which is what `launchctl asuser` does.

## macOS: the console user helper

When a certificate challenge arrives and the daemon is root, it:

1. Reads the System keychain itself, so MDM device identities are answered with no user
   session involved.
2. Resolves the console user with `SCDynamicStoreCopyConsoleUser`.
3. Launches itself as that user with
   `launchctl asuser <uid> sudo -u <user> -H netbird posture cert-proof`, writing the
   challenges to the child's stdin as JSON and reading proofs from its stdout.
4. Merges both sets of proofs, dropping a leaf that both keychains hold.

The child runs `RunHelper`, which uses the ordinary `KeychainStore` — inside the user's
session it simply works. **The private key never crosses the boundary; only the
signature and the certificate chain come back.**

`-H` matters: it sets `HOME`, which is how the login keychain path is resolved.

`netbird posture cert-proof` is hidden and not meant to be run by hand. It writes proofs
to stdout and every log line to stderr, so stdout stays parseable.

## Windows: the service and the signed-in user

`LocalMachine\MY` is what the service reads, and it is where AD and Intune enrol device
certificates. `CurrentUser\MY` lives in the signed-in user's registry hive with private
keys protected by DPAPI against their profile, so it is only readable while running as
that user.

The failure mode differs from macOS in an important way: a service that opens
`CURRENT_USER` does **not** get an error. "Current user" resolves to the service
account's own hive, `HKU\S-1-5-18`, so it silently reads an empty and irrelevant store.
There is nothing to log. That is why the service only ever opens `LocalMachine` and asks
a helper for the rest.

Windows does let a privileged service assume a user identity, which macOS does not for
keychains, so no external tooling is involved:

```go
windows.WTSQueryUserToken(session, &token)
cmd.SysProcAttr = &syscall.SysProcAttr{Token: syscall.Token(token), CreationFlags: windows.CREATE_NO_WINDOW}
```

`CREATE_NO_WINDOW` matters: without it a console window flashes on the user's desktop on
every sync.

Session selection prefers the physical console, then falls back to any active session,
so remote desktop and VDI hosts work. `WTSQueryUserToken` needs `SE_TCB_NAME`, which
LocalSystem holds and an ordinary process does not, so a user-run `netbird up` skips the
helper and reads the machine store alone.

In-process impersonation would also work, but it is per-OS-thread while goroutines
migrate freely, so it would need `runtime.LockOSThread` around every key operation. The
child process avoids that class of bug entirely.

Unlike macOS, the Windows store acquires keys with `CRYPT_ACQUIRE_SILENT_FLAG`, so a key
that would need a prompt fails immediately instead of blocking. That also means a
smartcard PIN can never be satisfied this way.

## Only the signed-in user can be validated

This is the central limitation of the design, and it is deliberate.

A proof from a user store can only ever be produced for **the user whose session is
currently open**. Consequences worth designing around:

- **At the sign-in screen there is no user proof.** macOS reports no console user or
  attributes the console to root, and `CurrentConsoleUser` returns false for both.
  Windows reports no active session with a token. Only machine proofs are sent, so a
  posture check that demands a user certificate fails on a machine nobody has signed
  into yet.
- **Signing out changes the answer.** Posture can flip between compliant and
  non-compliant across a sign-out, so management should treat "no proof" as its own
  state rather than as a failed check, or users get disconnected at the sign-in screen.
- **One session is asked, not all of them.** macOS asks the console user, so other
  fast-user-switched accounts are skipped even though their keychains are unlocked.
  Windows prefers the console and otherwise takes the first active session. If you ever
  need every signed-in user, both platforms would have to enumerate sessions and ask
  each one.
- **A locked keychain still blocks signing.** A user can be logged in with their
  keychain locked (locked on sleep, or manually). The helper then needs an unlock prompt
  and may block, which is why the spawn has a 30s timeout and a failure is reported as
  "no proof" rather than an error.
- **The first signature prompts.** The user sees "netbird wants to use your confidential
  information stored in ...". Choosing *Always Allow* records the helper's designated
  requirement in the key's ACL, so it persists across restarts and updates while the
  signing identity is stable. Unsigned or ad-hoc development builds re-prompt every run.

## What a user proof does and does not attest

It attests: *some process in that user's session had ACL permission to use a private key
whose certificate chains to CA X, and signed a nonce bound to this peer key*.

It does not attest that the daemon controls the key, that the key is hardware-bound, or
that a particular binary produced the signature. Any code running in that user's session
with an existing ACL grant can produce the same signature by calling
`SecKeyCreateSignature` directly — the proof format is not a secret. The helper does not
create that capability, it only packages it.

If you need a stronger guarantee, use a device identity that never involves a user
session (MDM into the System keychain, which the daemon reads directly), or a key that
requires user presence for each signature (Secure Enclave or a PIV token).

## Reading the logs

Everything in this path logs at info. A healthy macOS run shows, in order:

```
certificate posture: answering N certificate challenges from store *certproof.KeychainStore
macOS Security framework loaded for certificate posture, running as uid=0 euid=0
keychain search list contains 2 keychains
keychain search list[0]: /Library/Keychains/System.keychain
keychain identity query returned N items
certificate posture: asking the desktop session of "user" (uid 501) to answer N challenges
certificate posture: desktop session of "user" returned N proofs
peer meta carries N certificate posture proofs
```

Common outcomes and what they mean:

| Log line | Meaning |
| --- | --- |
| `keychain identity query returned errSecItemNotFound (-25300)` | The keychain is readable and holds no identity of that class. Any other OSStatus is a real access failure. |
| `holds no identities usable for certificate posture, but N readable certificates` | Reading works; the certificate is present without its private key, or is not there at all. |
| `no console user is logged in` | Login window. Device proofs only. |
| `has no issuer in the keychain` | The chain ships leaf-only and verifies only if the challenge supplies that exact root. |
| `challenge N rejected "..." : x509: unhandled critical extension` | The chain is fine but Go refuses an extension in it, which is common for Apple-issued certificates. |
| `challenge N matched none of the M candidates` | Every candidate was rejected; the preceding lines give the reason for each. |
