package bind

func GetGSOSize(control []byte) (int, error) {
	return wgConn.GetGSOSize(control)
}
