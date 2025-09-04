//go:build (linux && !android) || windows || (darwin && !ios)

package system

import (
	"sync"
)

var (
	staticInfo StaticInfo
	once       sync.Once
)

// StaticInfo is an object that contains machine information that does not change
type StaticInfo struct {
	SystemSerialNumber string
	SystemProductName  string
	SystemManufacturer string
	Environment        Environment

	// Windows specific fields
	OSName       string
	OSVersion    string
	BuildVersion string
}

func updateStaticInfo() {
	once.Do(func() {
		staticInfo = newStaticInfo()
	})
}

func getStaticInfo() StaticInfo {
	updateStaticInfo()
	return staticInfo
}
