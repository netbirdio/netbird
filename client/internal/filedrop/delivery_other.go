//go:build windows || js

package filedrop

func chownToDirOwner(string, string) error {
	return nil
}
