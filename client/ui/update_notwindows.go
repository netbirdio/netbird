//go:build !windows && !(linux && 386)

package main

func killParentUIProcess() {
	// No-op on non-Windows platforms
}
