package bind

import "fmt"

var (
	ErrUDPMUXNotSupported = fmt.Errorf("UDPMUX is not supported in WASM")
)
