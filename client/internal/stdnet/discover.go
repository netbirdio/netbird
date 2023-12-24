package stdnet

import "github.com/pion/transport/v3"

// ExternalIFaceDiscover provide an option for external services (mobile)
// to collect network interface information
type ExternalIFaceDiscover interface {
	// IFaces return with the description of the interfaces
	IFaces() (string, error)
}

type iFaceDiscover interface {
	iFaces() ([]*transport.Interface, error)
}
