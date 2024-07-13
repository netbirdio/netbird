//go:build !windows

package main

import "os"

func getUID() int {
	return os.Getuid()
}
