package util

import (
	"math/rand"
	"time"
)

// Retry retries a given toExec function calling onError on failed attempts
// onError shouldn be a lightweight function and shouldn't be blocking
func Retry(attempts int, sleep time.Duration, toExec func() error, onError func(e error)) error {
	if err := toExec(); err != nil {
		if s, ok := err.(stop); ok {
			return s.error
		}

		if attempts--; attempts > 0 {
			jitter := time.Duration(rand.Int63n(int64(sleep)))
			sleep += jitter / 2

			onError(err)
			time.Sleep(sleep)
			return Retry(attempts, 2*sleep, toExec, onError)
		}
		return err
	}

	return nil
}

type stop struct {
	error
}
