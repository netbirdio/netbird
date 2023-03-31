package stdnet

// IFaceDiscover provide an option for external services (mobile)
// to collect network interface information
type IFaceDiscover interface {
	// IFaces return with the description of the interfaces
	// todo refactor this to return []*transport.Interface instead to have it generic and independent from the platform
	IFaces() (string, error)
}
