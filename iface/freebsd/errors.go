package freebsd

import "errors"

var (
	ErrDoesNotExist     = errors.New("does not exist")
	ErrNameDoesNotMatch = errors.New("name does not match")
)
