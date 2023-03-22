package stdnet

type IFaceDiscover interface {
	IFaces() (string, error)
}
