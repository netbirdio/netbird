package ipcauth

// KnownForTest returns a copy of id marked as kernel-attested, so packages
// outside ipcauth can build identity fixtures. A real Identity is only ever
// produced by a peer-credential read, nothing outside a test should call this.
func KnownForTest(id Identity) Identity {
	id.known = true
	return id
}
