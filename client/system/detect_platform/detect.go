package detect_platform

import (
	"context"
	"net/http"
	"sync"
	"time"
)

var hc = &http.Client{Timeout: 300 * time.Millisecond}

func Detect(ctx context.Context) string {
	subCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	funcs := []func(context.Context) string{
		detectOpenStack,
		detectContainer,
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
