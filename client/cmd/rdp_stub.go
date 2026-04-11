//go:build !windows

package cmd

import "fmt"

// launchRDPClient is a stub for non-Windows platforms.
func launchRDPClient(peerIP string) error {
	fmt.Printf("RDP session authorized for %s\n", peerIP)
	fmt.Println("Note: mstsc.exe is only available on Windows.")
	fmt.Printf("Use any RDP client to connect to %s:3389\n", peerIP)
	return nil
}
