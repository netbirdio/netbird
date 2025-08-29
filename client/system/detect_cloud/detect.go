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

func Detect(ctx context.Context) string {
	subCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	funcs := []func(context.Context) string{
		detectAlibabaCloud,
		detectAWS,
		detectAzure,
		detectDigitalOcean,
		detectGCP,
		detectOracle,
		detectVultr,
	}

	results := make(chan string, len(funcs))

	var wg sync.WaitGroup

	for _, fn := range funcs {
		wg.Add(1)
		go func(f func(context.Context) string) {
			defer wg.Done()
			select {
			case <-subCtx.Done():
				return
			default:
				if result := f(ctx); result != "" {
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
