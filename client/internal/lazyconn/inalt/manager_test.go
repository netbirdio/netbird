package inalt

import (
	"testing"
	"time"
)

func init() {
	// Override the ticker factory for testing
	newTicker = func(d time.Duration) Ticker {
		return newFakeTicker(d)
	}
}

func TestNewManager(t *testing.T) {

}
