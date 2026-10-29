//go:build !linux

package tpm

import "io"

func open() (io.ReadWriteCloser, error) {
	return nil, ErrUnsupported
}
