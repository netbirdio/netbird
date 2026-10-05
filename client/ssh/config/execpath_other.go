//go:build !windows

package config

func shortExecPath(path string) (string, error) {
	return path, nil
}
