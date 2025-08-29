//go:build (linux && !android) || windows || (darwin && !ios)

package system

import (
	"context"
	"sync"
	"time"

	"github.com/netbirdio/netbird/client/system/detect_cloud"
	"github.com/netbirdio/netbird/client/system/detect_platform"
)

var (
	staticInfo StaticInfo
	once       sync.Once
)

func updateStaticInfo() StaticInfo {
	once.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		wg := sync.WaitGroup{}
		wg.Add(3)
		go func() {
			staticInfo.SystemSerialNumber, staticInfo.SystemProductName, staticInfo.SystemManufacturer = sysInfo()
			wg.Done()
		}()
		go func() {
			staticInfo.Environment.Cloud = detect_cloud.Detect(ctx)
			wg.Done()
		}()
		go func() {
			staticInfo.Environment.Platform = detect_platform.Detect(ctx)
			wg.Done()
		}()
		wg.Wait()
	})
	return staticInfo
}
