// go:build !linux
package bind

func GetGSOSize(control []byte) (int, error) {
	return 0, nil
}
