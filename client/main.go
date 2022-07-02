package main

import (
	"context"
	"fmt"
	"github.com/cenkalti/backoff/v4"
	log "github.com/sirupsen/logrus"
	"time"
)

func main() {

	for i := 0; i < 5; i++ {
		j := i
		go func() {
			try := 0
			b := backoff.WithContext(&backoff.ExponentialBackOff{
				InitialInterval:     800 * time.Millisecond,
				RandomizationFactor: 1,
				Multiplier:          1.7,
				MaxInterval:         10 * time.Second,
				MaxElapsedTime:      3 * 30 * 24 * time.Hour, // 3 months //todo make indefinite?
				Stop:                backoff.Stop,
				Clock:               backoff.SystemClock,
			}, context.Background())
			b.Reset()
			backoff.RetryNotify(func() error {
				return fmt.Errorf("error")
			}, b, func(err error, duration time.Duration) {
				log.Printf("routine %d -> try %d -> %v", j, try, duration)
				try++
				//fmt.Printf("%v;%v\n", time.Now().Format("2006-01-02 15:04:05"), duration.Seconds())
			})
		}()
	}

	select {}

	/*if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}*/
}
