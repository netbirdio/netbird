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

func Detect(mainCtx context.Context) string {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	detectVendorFuncs := []func(context.Context) string{
		detectAlibabaCloud,
		detectAWS,
		detectAzure,
		detectDigitalOcean,
		detectGCP,
		detectOracle,
		detectIBMCloud,
		detectSoftlayer,
		detectVultr,
	}

	detectSoftwareFuncs := []func(context.Context) string{
		detectOpenStack,
		detectContainer,
	}

	vendorResults := make(chan string, len(detectVendorFuncs))
	softwareResults := make(chan string, len(detectSoftwareFuncs))

	var wg sync.WaitGroup

	for _, fn := range detectVendorFuncs {
		wg.Add(1)
		go func(f func(context.Context) string) {
			defer wg.Done()
			select {
			case <-ctx.Done():
				return
			default:
				if result := f(mainCtx); result != "" {
					vendorResults <- result
					cancel()
				}
			}
		}(fn)
	}

	for _, fn := range detectSoftwareFuncs {
		wg.Add(1)
		go func(f func(context.Context) string) {
			defer wg.Done()
			select {
			case <-ctx.Done():
				return
			default:
				if result := f(mainCtx); result != "" {
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
