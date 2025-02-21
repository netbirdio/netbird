package internal

type WGIface interface {
	wgIfaceBase
	GetInterfaceGUIDString() (string, error)
}
