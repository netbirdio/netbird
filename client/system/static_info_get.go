//go:build (linux && !android) || (darwin && !ios)

package system

import (
	"context"
	"sync"
	"time"

	"github.com/netbirdio/netbird/client/system/detect_cloud"
	"github.com/netbirdio/netbird/client/system/detect_platform"
)

func getStaticInfo() StaticInfo {
	si := StaticInfo{}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	wg := sync.WaitGroup{}
	wg.Add(3)
	go func() {
		si.SystemSerialNumber, si.SystemProductName, si.SystemManufacturer = sysInfo()
		wg.Done()
	}()
	go func() {
		si.Environment.Cloud = detect_cloud.Detect(ctx)
		wg.Done()
	}()
	go func() {
		si.Environment.Platform = detect_platform.Detect(ctx)
		wg.Done()
	}()
	wg.Wait()
	return si
}
