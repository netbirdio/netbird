# TPM Manufacturer EK CA Certificates

These PEM files contain root and intermediate CA certificates from TPM manufacturers.
They are used by `VerifyAttestation` to verify the EK certificate chain, proving that
the enrollment key resides in real hardware.

## Updating

Run the fetch script to re-download:

    go run scripts/fetch-tpm-roots.go

After running, verify the SHA-256 checksums against each manufacturer's PKI portal
before committing updated files.

## Sources (as of 2026-04)

| File | Manufacturer | Source |
|------|-------------|--------|
| `infineon-rsa-ek-ca-063.pem` | Infineon | https://pki.infineon.com/ |
| `infineon-ecc-ek-ca-061.pem` | Infineon | https://pki.infineon.com/ |
| `stmicro-ek-root-ca-2.pem` | STMicroelectronics | https://tpm.st.com/st-tpm-ekroot/ |
| `amd-ftpm-ek-root-ca.pem` | AMD | https://ftpm.amd.com/pki/ |

## Dev mode

When this directory contains no `.pem` files, `BuildTPMRootPool` returns an empty pool.
The `VerifyAttestation` function detects an empty pool and skips the EK chain check,
logging a warning. AK signature verification still runs.
