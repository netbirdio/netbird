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
| Linux and others | PEM directory: `CertStoreDir` in the profile config, else `NB_CERT_STORE_DIR`, else `/etc/netbird/certs` | the daemon, directly |
| Linux | a `TSS2 PRIVATE KEY` file in that directory, signed by the TPM | the daemon, through `/dev/tpmrm0` |
| Linux | a PKCS#11 token, tpm2-pkcs11 for one, enabled by `CertPKCS11PIN` in the profile config | the daemon, through the token's module, in builds with the `pkcs11` tag |

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

## Linux: keys held by the TPM

Enrollment tooling on Linux keeps a TPM-resident key as a `TSS2 PRIVATE KEY` PEM file,
the format of draft-bottomley-tpm2-keys that tpm2-openssl, tpm2-tss-engine and
`tpm2_encodeobject` write. The file holds the key wrapped by its parent; the TPM is the
only thing that can use it. Drop it next to the certificate as usual:

```
openssl genpkey -provider tpm2 -algorithm EC -pkeyopt group:P-256 -out /etc/netbird/certs/device.key
openssl req -provider tpm2 -provider default -new -key /etc/netbird/certs/device.key -subj /CN=device -out device.csr
```

Sign the CSR with the organisation CA and store the result as `device.pem`. The store
parses the key file without touching the TPM, so the certificate is listed as a
candidate like any other, and every signature opens `/dev/tpmrm0`, loads the key under
its parent, signs, flushes and closes again. `NB_TPM_DEVICE` overrides the device path.

What the key file may look like:

- **Parent.** A persistent handle such as `0x81000001` is used as is. The owner
  hierarchy, which both tpm2-openssl and tpm2-tss-engine default to, means the key was
  created under a transient primary from the TCG default ECC P-256 template, and that
  same primary is derived again before loading.
- **No authorization value.** A key created with a password needs someone to type it,
  which the daemon cannot arrange, so the certificate is skipped with a log line rather
  than blocking on a TPM auth failure.
- **RSA-2048 or P-256, sometimes P-384.** Those are what the PC Client profile requires
  of a TPM; P-384 depends on the chip. The TPM chooses the RSA-PSS salt itself, which is
  why management verifies PSS proofs with `rsa.PSSSaltLengthAuto`.

Windows needs none of this: a certificate enrolled into the TPM sits behind the Microsoft
Platform Crypto Provider and the CNG path above signs with it unchanged. macOS has no
TPM; its Secure Enclave keys are reachable only through the keychain path.

To exercise the path without hardware, run a software TPM and point the end-to-end test
at it:

```
swtpm socket --tpm2 --server type=unixio,path=/tmp/swtpm.sock --ctrl type=unixio,path=/tmp/swtpm.ctrl --flags not-need-init,startup-clear
NB_TPM_DEVICE=/tmp/swtpm.sock go test ./client/internal/certproof/ -run TestCollect_TPMKeyEndToEnd -v
```

## Linux: keys behind a PKCS#11 token

Distributions that follow Red Hat's guidance reach the TPM through tpm2-pkcs11, a PKCS#11
module whose token holds both the key and, after `tpm2_ptool addcert`, the certificate.
The store reads that token when the profile config, `/etc/netbird/config.json` by default,
carries the token's user PIN:

```json
"CertPKCS11PIN": "1234"
```

That alone opens the first token the p11-kit proxy exposes, which is tpm2-pkcs11 on a
stock setup that has registered it. `CertPKCS11URI`, an RFC 7512 URI, narrows that down
on a host with several tokens or without p11-kit:

```json
"CertPKCS11URI": "pkcs11:token=netbird?module-path=/usr/lib/x86_64-linux-gnu/libtpm2_pkcs11.so"
```

`token` selects the token by label, or the first token present when absent. `module-path`
names the library to load; `module-name=tpm2_pkcs11` resolves to `libtpm2_pkcs11.so` on
the loader's search path, and with neither the p11-kit proxy is loaded, which exposes every
module the system has registered. The URI may carry the PIN itself, as `pin-value` inline
or `pin-source` naming a file, and `CertPKCS11PIN` takes precedence over both. Without any
PIN no login happens, and tpm2-pkcs11 then shows no private keys at all. Every other
attribute is ignored.

The certificate may live on the token or in the PEM directory: `CertStoreDir` in the
profile config, else `NB_CERT_STORE_DIR`, else `/etc/netbird/certs`. On the token,
certificates and private keys are paired by `CKA_ID`,
which is what `tpm2_ptool addcert` and `pkcs11-tool` set. In the directory, a certificate
file without a key of its own is paired with the token key whose public key it carries, so
`device.pem` alone next to a key that only the TPM holds is enough; the token's public key
object, which `tpm2_ptool addkey` and `import` create alongside the private one, is what
the store compares against. Chains are completed from the certificates on the token and in
the directory together, so intermediates may sit in either place.

Each operation opens a session, logs in, works, logs out and closes, so no token handle
outlives a call, and the PEM directory keeps working when the token does not: the two are
queried together and a failing token is logged rather than hiding file certificates.

Two consequences of the PIN are worth knowing. It is a secret on disk, which the profile
config already is: it holds the WireGuard private key and is written readable by root
alone, and the debug bundle's config dump leaves `CertPKCS11PIN` out. And a wrong PIN
counts against the TPM's dictionary-attack lockout, which is shared with everything else
on the machine that uses the TPM.

The module is loaded at runtime without cgo, through `purego`, which means the binary is
dynamically linked against libc. The store is therefore compiled in only with `-tags pkcs11`
on linux/amd64 and linux/arm64: the deb and rpm packages are built that way, since they
target glibc distributions, while the release tarballs and the Alpine-based container
images keep the fully static build. Without the tag, setting `CertPKCS11PIN` logs that
the build lacks the support.

To exercise the path without hardware, initialise a SoftHSM token and run the end-to-end
test, which imports a key and certificate itself:

```
softhsm2-util --init-token --free --label netbird --pin 1234 --so-pin 1234
NB_TEST_PKCS11_URI='pkcs11:token=netbird?module-path=/usr/lib/softhsm/libsofthsm2.so&pin-value=1234' \
  go test -tags pkcs11 ./client/internal/certproof/ -run PKCS11 -v
```

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
