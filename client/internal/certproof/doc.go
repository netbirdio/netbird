// Package certproof answers certificate posture challenges: it finds the certificates a
// peer holds a private key for and signs the challenge nonce, bound to the peer's
// WireGuard key, with that key. Management verifies the signature and the chain against
// the CAs of the check, so only a holder of the key passes and a proof made for one peer
// cannot be replayed by another. Keys in the OS stores, the TPM and a PKCS#11 token are
// used through the platform, which signs; a plain PEM key file is the exception, parsed
// and used in the daemon's memory.
//
// Machine stores are read by the daemon itself: the Windows LocalMachine store, the macOS
// System keychain, and on Linux a directory of PEM files, TSS2 key files the TPM signs
// with, and a PKCS#11 token. On Linux the directory and the token URI come from the
// daemon's environment (NB_CERT_STORE_DIR, NB_CERT_PKCS11_URI), as does the token PIN
// (NB_TPM_PIN); none of them is read from the profile config.
//
// User stores cannot be read by a privileged daemon, so it starts this binary as
// "netbird posture cert-proof" inside the user's session and receives only signatures
// and chains on its stdout. On macOS uid is not what unlocks a login keychain, the
// session's bootstrap namespace is, which is why the helper enters it through launchctl
// asuser. On Windows a service opening CURRENT_USER silently reads its own empty hive, so
// the helper runs with the session's token instead. Its output is untrusted: sizes are
// capped and only proofs for requested nonces are kept.
//
// A user proof shows that some process in that user's session could use a key whose
// certificate chains to the CA. It does not show which binary signed, or that the key is
// hardware-bound; device stores are the stronger signal.
package certproof
