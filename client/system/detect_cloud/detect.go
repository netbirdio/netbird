package detect_cloud

import (
	"context"
	"net/http"
	"sync"
	"time"
)

/*
	This packages is inspired by the work of the original author (https://github.com/perlogix), but it has been modified to fit the needs of the project.
	Original project: https://github.com/perlogix/libdetectcloud
*/

var hc = &http.Client{Timeout: 300 * time.Millisecond}

func Detect() string {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	detectVendorFuncs := []func() string{
		detectAlibabaCloud,
		detectAWS,
		detectAzure,
		detectDigitalOcean,
		detectGCE,
		detectOracle,
		detectIBMCloud,
		detectSoftlayer,
		detectVultr,
	}

	detectSoftwareFuncs := []func() string{
		detectOpenStack,
		detectContainer,
	}

	vendorResults := make(chan string, len(detectVendorFuncs))
	softwareResults := make(chan string, len(detectSoftwareFuncs))

	var wg sync.WaitGroup
	wg.Add(len(detectVendorFuncs) + len(detectSoftwareFuncs))

	for _, fn := range detectVendorFuncs {
		go func(f func() string) {
			defer wg.Done()
			select {
			case <-ctx.Done():
				return
			default:
				if result := f(); result != "" {
					vendorResults <- result
					cancel()
				}
			}
		}(fn)
	}

	for _, fn := range detectSoftwareFuncs {
		go func(f func() string) {
			defer wg.Done()
			select {
			case <-ctx.Done():
				return
			default:
				if result := f(); result != "" {
					softwareResults <- result
				}
			}
		}(fn)
	}

	go func() {
		wg.Wait()
		close(vendorResults)
		close(softwareResults)
	}()

	for result := range vendorResults {
		if result != "" {
			return result
		}
	}

	for result := range softwareResults {
		if result != "" {
			return result
		}
	}

	return ""
}
