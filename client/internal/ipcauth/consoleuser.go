package ipcauth

// ActiveIdentity returns the Identity of the currently active console / GUI
// session user, and true if such a user exists. Used to gate ownership
// TOFU (auto-claim). Returns false on platforms without a console concept
// (ios, android), on headless servers with no active session, or on lookup
// failure.
func ActiveIdentity() (Identity, bool) {
	return activeIdentity()
}
