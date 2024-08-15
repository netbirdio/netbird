//go:build android || (ios && !darwin)
// +build android ios,!darwin

package iface

import "errors"

func DestroyInterface(name string) error {
	return errors.New("not supported on mobile")
}
