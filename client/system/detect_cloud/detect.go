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

	detectFuncs := []func() string{
		detectAlibabaCloud,
		detectAWS,
		detectAzure,
		detectDigitalOcean,
		detectGCE,
		detectOracle,
		detectIBMCloud,
		detectSoftlayer,
		detectVultr,
		detectContainer,
	}

	results := make(chan string, len(detectFuncs))

	var wg sync.WaitGroup
	wg.Add(len(detectFuncs))

	for _, fn := range detectFuncs {
		go func(f func() string) {
			defer wg.Done()
			select {
			case <-ctx.Done():
				return
			default:
				if result := f(); result != "" {
					results <- result
					cancel()
				}
			}
		}(fn)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	for result := range results {
		if result != "" {
			return result
		}
	}

	return ""
}
