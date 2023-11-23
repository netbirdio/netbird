package users

import (
	"fmt"
	"strings"
	"time"

	"github.com/netbirdio/netbird/management/server/idp"
)

const (
	UserRoleAdmin   UserRole = "admin"
	UserRoleUser    UserRole = "user"
	UserRoleUnknown UserRole = "unknown"

	UserStatusActive   UserStatus = "active"
	UserStatusDisabled UserStatus = "disabled"
	UserStatusInvited  UserStatus = "invited"

	UserIssuedAPI         = "api"
	UserIssuedIntegration = "integration"
)

type UserInfo struct {
	ID                   string               `json:"id"`
	Email                string               `json:"email"`
	Name                 string               `json:"name"`
	Role                 string               `json:"role"`
	AutoGroups           []string             `json:"auto_groups"`
	Status               string               `json:"-"`
	IsServiceUser        bool                 `json:"is_service_user"`
	IsBlocked            bool                 `json:"is_blocked"`
	NonDeletable         bool                 `json:"non_deletable"`
	LastLogin            time.Time            `json:"last_login"`
	Issued               string               `json:"issued"`
	IntegrationReference IntegrationReference `json:"-"`
}

// StrRoleToUserRole returns UserRole for a given strRole or UserRoleUnknown if the specified role is unknown
func StrRoleToUserRole(strRole string) UserRole {
	switch strings.ToLower(strRole) {
	case "admin":
		return UserRoleAdmin
	case "user":
		return UserRoleUser
	default:
		return UserRoleUnknown
	}
}

// UserStatus is the status of a User
type UserStatus string

// UserRole is the role of a User
type UserRole string

// IntegrationReference holds the reference to a particular integration
type IntegrationReference struct {
	ID              int
	IntegrationType string
}

func (ir IntegrationReference) String() string {
	return fmt.Sprintf("%s:%d", ir.IntegrationType, ir.ID)
}

func (ir IntegrationReference) CacheKey(path ...string) string {
	if len(path) == 0 {
		return ir.String()
	}
	return fmt.Sprintf("%s:%s", ir.String(), strings.Join(path, ":"))
}

// User represents a user of the system
type User struct {
	Id string `gorm:"primaryKey"`
	// AccountID is a reference to Account that this object belongs
	AccountID     string `json:"-" gorm:"index"`
	Role          UserRole
	IsServiceUser bool
	// NonDeletable indicates whether the service user can be deleted
	NonDeletable bool
	// ServiceUserName is only set if IsServiceUser is true
	ServiceUserName string
	// AutoGroups is a list of Group IDs to auto-assign to peers registered by this user
	AutoGroups []string                        `gorm:"serializer:json"`
	PATs       map[string]*PersonalAccessToken `gorm:"-"`
	PATsG      []PersonalAccessToken           `json:"-" gorm:"foreignKey:UserID;references:id"`
	// Blocked indicates whether the user is blocked. Blocked users can't use the system.
	Blocked bool
	// LastLogin is the last time the user logged in to IdP
	LastLogin time.Time

	// Issued of the user
	Issued string `gorm:"default:api"`

	IntegrationReference IntegrationReference `gorm:"embedded;embeddedPrefix:integration_ref_"`
}

// IsBlocked returns true if the user is blocked, false otherwise
func (u *User) IsBlocked() bool {
	return u.Blocked
}

func (u *User) LastDashboardLoginChanged(LastLogin time.Time) bool {
	return LastLogin.After(u.LastLogin) && !u.LastLogin.IsZero()
}

// IsAdmin returns true if the user is an admin, false otherwise
func (u *User) IsAdmin() bool {
	return u.Role == UserRoleAdmin
}

// ToUserInfo converts a User object to a UserInfo object.
func (u *User) ToUserInfo(userData *idp.UserData) (*UserInfo, error) {
	autoGroups := u.AutoGroups
	if autoGroups == nil {
		autoGroups = []string{}
	}

	if userData == nil {
		return &UserInfo{
			ID:            u.Id,
			Email:         "",
			Name:          u.ServiceUserName,
			Role:          string(u.Role),
			AutoGroups:    u.AutoGroups,
			Status:        string(UserStatusActive),
			IsServiceUser: u.IsServiceUser,
			IsBlocked:     u.Blocked,
			LastLogin:     u.LastLogin,
			Issued:        u.Issued,
		}, nil
	}
	if userData.ID != u.Id {
		return nil, fmt.Errorf("wrong UserData provided for user %s", u.Id)
	}

	userStatus := UserStatusActive
	if userData.AppMetadata.WTPendingInvite != nil && *userData.AppMetadata.WTPendingInvite {
		userStatus = UserStatusInvited
	}

	return &UserInfo{
		ID:            u.Id,
		Email:         userData.Email,
		Name:          userData.Name,
		Role:          string(u.Role),
		AutoGroups:    autoGroups,
		Status:        string(userStatus),
		IsServiceUser: u.IsServiceUser,
		IsBlocked:     u.Blocked,
		LastLogin:     u.LastLogin,
		Issued:        u.Issued,
	}, nil
}

// Copy the user
func (u *User) Copy() *User {
	autoGroups := make([]string, len(u.AutoGroups))
	copy(autoGroups, u.AutoGroups)
	pats := make(map[string]*PersonalAccessToken, len(u.PATs))
	for k, v := range u.PATs {
		pats[k] = v.Copy()
	}
	return &User{
		Id:                   u.Id,
		AccountID:            u.AccountID,
		Role:                 u.Role,
		AutoGroups:           autoGroups,
		IsServiceUser:        u.IsServiceUser,
		NonDeletable:         u.NonDeletable,
		ServiceUserName:      u.ServiceUserName,
		PATs:                 pats,
		Blocked:              u.Blocked,
		LastLogin:            u.LastLogin,
		Issued:               u.Issued,
		IntegrationReference: u.IntegrationReference,
	}
}

// NewUser creates a new user
func NewUser(id string, role UserRole, isServiceUser bool, nonDeletable bool, serviceUserName string, autoGroups []string, issued string) *User {
	return &User{
		Id:              id,
		Role:            role,
		IsServiceUser:   isServiceUser,
		NonDeletable:    nonDeletable,
		ServiceUserName: serviceUserName,
		AutoGroups:      autoGroups,
		Issued:          issued,
	}
}

// NewRegularUser creates a new user with role UserRoleUser
func NewRegularUser(id string) *User {
	return NewUser(id, UserRoleUser, false, false, "", []string{}, UserIssuedAPI)
}

// NewAdminUser creates a new user with role UserRoleAdmin
func NewAdminUser(id string) *User {
	return NewUser(id, UserRoleAdmin, false, false, "", []string{}, UserIssuedAPI)
}
