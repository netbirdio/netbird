package status

import (
	"errors"
	"fmt"

	"github.com/netbirdio/netbird/shared/management/operations"
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

	// TooManyRequests indicates that the user has sent too many requests in a given amount of time (rate limiting)
	TooManyRequests Type = 11
)

// Type is a type of the Error
type Type int32

var (
	ErrExtraSettingsNotFound = errors.New("extra settings not found")
	ErrPeerAlreadyLoggedIn   = errors.New("peer with the same public key is already logged in")
)

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
func NewAccountNotFoundError(accountKey string) error {
	return Errorf(NotFound, "account not found: %s", accountKey)
}

// NewAccountOnboardingNotFoundError creates a new Error with NotFound type for a missing account onboarding
func NewAccountOnboardingNotFoundError(accountKey string) error {
	return Errorf(NotFound, "account onboarding not found: %s", accountKey)
}

// NewPeerNotPartOfAccountError creates a new Error with PermissionDenied type for a peer not being part of an account
func NewPeerNotPartOfAccountError() error {
	return Errorf(PermissionDenied, "peer is not part of this account")
}

// NewUserNotFoundError creates a new Error with NotFound type for a missing user
func NewUserNotFoundError(userKey string) error {
	return Errorf(NotFound, "user: %s not found", userKey)
}

// NewUserBlockedError creates a new Error with PermissionDenied type for a blocked user
func NewUserBlockedError() error {
	return Errorf(PermissionDenied, "user is blocked")
}

// NewUserPendingApprovalError creates a new Error with PermissionDenied type for a blocked user pending approval
func NewUserPendingApprovalError() error {
	return Errorf(PermissionDenied, "user is pending approval")
}

// NewPeerNotRegisteredError creates a new Error with Unauthenticated type unregistered peer
func NewPeerNotRegisteredError() error {
	return Errorf(Unauthenticated, "peer is not registered")
}

// NewPeerLoginMismatchError creates a new Error with Unauthenticated type for a peer that is already registered for another user
func NewPeerLoginMismatchError() error {
	return Errorf(Unauthenticated, "peer is already registered by a different User or a Setup Key")
}

// NewPeerLoginExpiredError creates a new Error with PermissionDenied type for an expired peer
func NewPeerLoginExpiredError() error {
	return Errorf(PermissionDenied, "peer login has expired, please log in once more")
}

// NewSetupKeyNotFoundError creates a new Error with NotFound type for a missing setup key
func NewSetupKeyNotFoundError(setupKeyID string) error {
	return Errorf(NotFound, "setup key: %s not found", setupKeyID)
}

func NewGetAccountFromStoreError(err error) error {
	return Errorf(Internal, "issue getting account from store: %s", err)
}

// NewUserNotPartOfAccountError creates a new Error with PermissionDenied type for a user not being part of an account
func NewUserNotPartOfAccountError() error {
	return Errorf(PermissionDenied, "user is not part of this account")
}

// NewGetUserFromStoreError creates a new Error with Internal type for an issue getting user from store
func NewGetUserFromStoreError() error {
	return Errorf(Internal, "issue getting user from store")
}

// NewAdminPermissionError creates a new Error with PermissionDenied type for actions requiring admin role.
func NewAdminPermissionError() error {
	return Errorf(PermissionDenied, "admin role required to perform this action")
}

// NewInvalidKeyIDError creates a new Error with InvalidArgument type for an issue getting a setup key
func NewInvalidKeyIDError() error {
	return Errorf(InvalidArgument, "invalid key ID")
}

// NewGetAccountError creates a new Error with Internal type for an issue getting account
func NewGetAccountError(err error) error {
	return Errorf(Internal, "error getting account: %s", err)
}

// NewGroupNotFoundError creates a new Error with NotFound type for a missing group
func NewGroupNotFoundError(groupID string) error {
	return Errorf(NotFound, "group: %s not found", groupID)
}

// NewPostureChecksNotFoundError creates a new Error with NotFound type for a missing posture checks
func NewPostureChecksNotFoundError(postureChecksID string) error {
	return Errorf(NotFound, "posture checks: %s not found", postureChecksID)
}

// NewPolicyNotFoundError creates a new Error with NotFound type for a missing policy
func NewPolicyNotFoundError(policyID string) error {
	return Errorf(NotFound, "policy: %s not found", policyID)
}

// NewNameServerGroupNotFoundError creates a new Error with NotFound type for a missing name server group
func NewNameServerGroupNotFoundError(nsGroupID string) error {
	return Errorf(NotFound, "nameserver group: %s not found", nsGroupID)
}

// NewNetworkNotFoundError creates a new Error with NotFound type for a missing network.
func NewNetworkNotFoundError(networkID string) error {
	return Errorf(NotFound, "network: %s not found", networkID)
}

// NewNetworkRouterNotFoundError creates a new Error with NotFound type for a missing network router.
func NewNetworkRouterNotFoundError(routerID string) error {
	return Errorf(NotFound, "network router: %s not found", routerID)
}

// NewNetworkResourceNotFoundError creates a new Error with NotFound type for a missing network resource.
func NewNetworkResourceNotFoundError(resourceID string) error {
	return Errorf(NotFound, "network resource: %s not found", resourceID)
}

// NewPermissionDeniedError creates a new Error with PermissionDenied type for a permission denied error.
func NewPermissionDeniedError() error {
	return Errorf(PermissionDenied, "permission denied")
}

func NewPermissionValidationError(err error) error {
	return Errorf(PermissionDenied, "failed to validate user permissions: %s", err)
}

func NewResourceNotPartOfNetworkError(resourceID, networkID string) error {
	return Errorf(BadRequest, "resource %s is not part of the network %s", resourceID, networkID)
}

func NewRouterNotPartOfNetworkError(routerID, networkID string) error {
	return Errorf(BadRequest, "router %s is not part of the network %s", routerID, networkID)
}

// NewServiceUserRoleInvalidError creates a new Error with InvalidArgument type for creating a service user with owner role
func NewServiceUserRoleInvalidError() error {
	return Errorf(InvalidArgument, "can't create a service user with owner role")
}

// NewOwnerDeletePermissionError creates a new Error with PermissionDenied type for attempting
// to delete a user with the owner role.
func NewOwnerDeletePermissionError() error {
	return Errorf(PermissionDenied, "can't delete a user with the owner role")
}

func NewPATNotFoundError(patID string) error {
	return Errorf(NotFound, "PAT: %s not found", patID)
}

func NewExtraSettingsNotFoundError() error {
	return ErrExtraSettingsNotFound
}

func NewUserRoleNotFoundError(role string) error {
	return Errorf(NotFound, "user role: %s not found", role)
}

func NewOperationNotFoundError(operation operations.Operation) error {
	return Errorf(NotFound, "operation: %s not found", operation)
}

func NewRouteNotFoundError(routeID string) error {
	return Errorf(NotFound, "route: %s not found", routeID)
}

// NewZoneNotFoundError creates a new Error with NotFound type for a missing dns zone.
func NewZoneNotFoundError(zoneID string) error {
	return Errorf(NotFound, "zone: %s not found", zoneID)
}

// NewDNSRecordNotFoundError creates a new Error with NotFound type for a missing dns record.
func NewDNSRecordNotFoundError(recordID string) error {
	return Errorf(NotFound, "dns record: %s not found", recordID)
}

func NewResourceInUseError(resourceID string, proxyID string) error {
	return Errorf(PreconditionFailed, "resource %s is in use by proxy %s", resourceID, proxyID)
}

func NewPeerInUseError(peerID string, proxyID string) error {
	return Errorf(PreconditionFailed, "peer %s is in use by proxy %s", peerID, proxyID)
}
