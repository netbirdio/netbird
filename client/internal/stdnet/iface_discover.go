package stdnet

// IFaceDiscover provide an option for external services (mobile)
// to collect network interface information
type IFaceDiscover interface {
	// IFaces return with the description of the interfaces
	IFaces() (string, error)
}
