//go:build !darwin || ios

package sleep

import "fmt"

func NewDetector() (detector, error) {
	return nil, fmt.Errorf("sleep not supported on this platform")
}
