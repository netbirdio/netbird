package status

import (
	"errors"
	"fmt"
)

const (
	// UserAlreadyExists indicates that user already exists
	UserAlreadyExists Type = 1

	// PreconditionFailed indicates that some pre-condition for the operation hasn't been fulfilled
	PreconditionFailed Type = 2

	// PermissionDenied indicates that user has no permissions to view data
	PermissionDenied Type = 3

	// NotFound indicates that the object wasn't found in the system (or under a given Account)
	NotFound Type = 4

	// Internal indicates some generic internal error
	Internal Type = 5

	// InvalidArgument indicates some generic invalid argument error
	InvalidArgument Type = 6

	// AlreadyExists indicates a generic error when an object already exists in the system
	AlreadyExists Type = 7

	// Unauthorized indicates that user is not authorized
	Unauthorized Type = 8

	// BadRequest indicates that user is not authorized
	BadRequest Type = 9

	// Unauthenticated indicates that user is not authenticated due to absence of valid credentials
	Unauthenticated Type = 10
)

// Type is a type of the Error
type Type int32

// Error is an internal error
type Error struct {
	ErrorType Type
	Message   string
}

// Type returns the Type of the error
func (e *Error) Type() Type {
	return e.ErrorType
}

// Error is an error string
func (e *Error) Error() string {
	return e.Message
}

// Errorf returns Error(ErrorType, fmt.Sprintf(format, a...)).
func Errorf(errorType Type, format string, a ...interface{}) error {
	return &Error{
		ErrorType: errorType,
		Message:   fmt.Sprintf(format, a...),
	}
}

// FromError returns Error, true if the provided error is of type of Error. nil, false otherwise
func FromError(err error) (s *Error, ok bool) {
	if err == nil {
		return nil, true
	}
	var e *Error
	if errors.As(err, &e) {
		return e, true
	}
	return nil, false
}

// NewPeerNotFoundError creates a new Error with NotFound type for a missing peer
func NewPeerNotFoundError(peerKey string) error {
	return Errorf(NotFound, "peer not found: %s", peerKey)
}

// NewAccountNotFoundError creates a new Error with NotFound type for a missing account
func NewAccountNotFoundError() error {
	return Errorf(NotFound, "account not found")
}

// NewUserNotFoundError creates a new Error with NotFound type for a missing user
func NewUserNotFoundError(userKey string) error {
	return Errorf(NotFound, "user not found: %s", userKey)
}

// NewPeerNotRegisteredError creates a new Error with NotFound type for a missing peer
func NewPeerNotRegisteredError() error {
	return Errorf(Unauthenticated, "peer is not registered")
}

// NewPeerLoginExpiredError creates a new Error with PermissionDenied type for an expired peer
func NewPeerLoginExpiredError() error {
	return Errorf(PermissionDenied, "peer login has expired, please log in once more")
}

func NewGetAccountFromStoreError(err error) error {
	return Errorf(Internal, "issue getting account from store: %s", err)
}

func NewUnauthorizedToViewAccountSettingError() error {
	return Errorf(PermissionDenied, "only users with admin power can view account settings")
}

// NewUserNotPartOfAccountError creates a new Error with PermissionDenied type for a user not being part of an account
func NewUserNotPartOfAccountError() error {
	return Errorf(PermissionDenied, "user is not part of this account")
}

// NewGetUserFromStoreError creates a new Error with Internal type for an issue getting user from store
func NewGetUserFromStoreError() error {
	return Errorf(Internal, "issue getting user from store")
}

func NewUnauthorizedToViewUsersError() error {
	return Errorf(PermissionDenied, "only users with admin power can view users")
}

func NewUnauthorizedToViewServiceUsersError() error {
	return Errorf(PermissionDenied, "only users with admin power can view service users")
}

// NewServiceUserRoleInvalidError creates a new Error with InvalidArgument type for creating a service user with owner role
func NewServiceUserRoleInvalidError() error {
	return Errorf(InvalidArgument, "can't create a service user with owner role")
}

// NewInvalidKeyIDError creates a new Error with InvalidArgument type for an issue getting a setup key
func NewInvalidKeyIDError() error {
	return Errorf(InvalidArgument, "invalid key ID")
}

// NewSetupKeyNotFoundError creates a new Error with NotFound type for a missing setup key
func NewSetupKeyNotFoundError(err error) error {
	return Errorf(NotFound, "setup key not found: %s", err)
}

// NewUnauthorizedToViewSetupKeysError creates a new Error with Unauthorized type for an issue getting a setup key
func NewUnauthorizedToViewSetupKeysError() error {
	return Errorf(PermissionDenied, "only users with admin power can view setup keys")
}

func NewGroupNotFoundError() error {
	return Errorf(NotFound, "group not found")
}

func NewUnauthorizedToViewGroupsError() error {
	return Errorf(PermissionDenied, "only users with admin power can view groups")
}

func NewPATNotFoundError() error {
	return Errorf(NotFound, "PAT not found")
}

func NewGetPATFromStoreError() error {
	return Errorf(Internal, "issue getting pat from store")
}

func NewUnauthorizedToViewPATsError() error {
	return Errorf(PermissionDenied, "only users with admin power can view PATs")
}

func NewUnauthorizedToViewPoliciesError() error {
	return Errorf(PermissionDenied, "only users with admin power can view policies")
}

func NewUnauthorizedToViewPostureChecksError() error {
	return Errorf(PermissionDenied, "only users with admin power can view posture checks")
}

func NewUnauthorizedToViewDNSSettingsError() error {
	return Errorf(PermissionDenied, "only users with admin power can view dns settings")
}

func NewUnauthorizedToViewNSGroupsError() error {
	return Errorf(PermissionDenied, "only users with admin power can view name server groups")
}

func NewUnauthorizedToViewRoutesError() error {
	return Errorf(PermissionDenied, "only users with admin power can view network routes")
}
