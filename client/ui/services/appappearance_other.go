//go:build !(linux && cgo)

package services

// setAppAppearance is a no-op where the platform has no app-wide appearance to
// set; macOS and Windows theme each window instead, via setWindowAppearance.
func setAppAppearance(bool) {}
