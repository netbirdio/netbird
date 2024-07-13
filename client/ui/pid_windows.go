package main

import "golang.org/x/sys/windows"

func getUID() int {
	return windows.Getuid()
}
