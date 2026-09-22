//go:build !windows

package util

// readJsonShareMode reads a JSON file into res. Only Windows needs a share
// mode to keep a reader from blocking a rename over the file it is reading.
func readJsonShareMode(file string, res interface{}) (interface{}, error) {
	return ReadJson(file, res)
}
