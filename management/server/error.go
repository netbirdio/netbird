package server

import (
	"fmt"
)

const (
	// UserAlreadyExists indicates that user already exists
	UserAlreadyExists ErrorType = iota
	// AccountNotFound indicates that specified account hasn't been found
	AccountNotFound
	// PreconditionFailed indicates that some pre-condition for the operation hasn't been fulfilled
	PreconditionFailed

	// UserNotFound indicates that user wasn't found in the system (or under a given Account)
	UserNotFound

	// PermissionDenied indicates that user has no permissions to view data
	PermissionDenied

	// SetupKeyNotFound indicates that the setup key wasn't found in the system (or under a given Account)
	SetupKeyNotFound

	// GroupNotFound indicates that the group wasn't found in the system (or under a given Account)
	GroupNotFound

	// RouteNotFound indicates that the route wasn't found in the system (or under a given Account)
	RouteNotFound

	// RuleNotFound indicates that the rule wasn't found in the system (or under a given Account)
	RuleNotFound
)

// ErrorType is a type of the Error
type ErrorType int32

// Error is an internal error
type Error struct {
	errorType ErrorType
	message   string
}

// Type returns the Type of the error
func (e *Error) Type() ErrorType {
	return e.errorType
}

// Error is an error string
func (e *Error) Error() string {
	return e.message
}

// Errorf returns Error(errorType, fmt.Sprintf(format, a...)).
func Errorf(errorType ErrorType, format string, a ...interface{}) error {
	return &Error{
		errorType: errorType,
		message:   fmt.Sprintf(format, a...),
	}
}

// FromError returns Error, true if the provided error is of type of Error. nil, false otherwise
func FromError(err error) (s *Error, ok bool) {
	if err == nil {
		return nil, true
	}
	if e, ok := err.(*Error); ok {
		return e, true
	}
	return nil, false
}
