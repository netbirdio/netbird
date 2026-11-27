package types

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/netbirdio/netbird/management/server/idp"
	"github.com/netbirdio/netbird/shared/management/integration_reference"
	"github.com/netbirdio/netbird/util/crypt"
)

const (
	UserRoleOwner             UserRole = "owner"
	UserRoleAdmin             UserRole = "admin"
	UserRoleUser              UserRole = "user"
	UserRoleUnknown           UserRole = "unknown"
	UserRoleBillingAdmin      UserRole = "billing_admin"
	UserRoleAuditor           UserRole = "auditor"
	UserRoleNetworkAdmin      UserRole = "network_admin"
	UserRoleAgentNetworkAdmin UserRole = "agent_network_admin"
	UserRoleUsageViewer       UserRole = "usage_viewer"

	UserStatusActive   UserStatus = "active"
	UserStatusDisabled UserStatus = "disabled"
	UserStatusInvited  UserStatus = "invited"

	UserIssuedAPI         = "api"
	UserIssuedIntegration = "integration"
)

// StrRoleToUserRole returns UserRole for a given strRole or UserRoleUnknown if the specified role is unknown
func StrRoleToUserRole(strRole string) UserRole {
	switch strings.ToLower(strRole) {
	case "owner":
		return UserRoleOwner
	case "admin":
		return UserRoleAdmin
	case "user":
		return UserRoleUser
	case "billing_admin":
		return UserRoleBillingAdmin
	case "auditor":
		return UserRoleAuditor
	case "network_admin":
		return UserRoleNetworkAdmin
	case "agent_network_admin":
		return UserRoleAgentNetworkAdmin
	case "usage_viewer":
		return UserRoleUsageViewer
	default:
		return UserRoleUnknown
	}
}

// UserStatus is the status of a User
type UserStatus string

// UserRole is the role of a User
type UserRole string

type UserInfo struct {
	ID                   string                                     `json:"id"`
	Email                string                                     `json:"email"`
	Name                 string                                     `json:"name"`
	Role                 string                                     `json:"role"`
	AutoGroups           []string                                   `json:"auto_groups"`
	Status               string                                     `json:"-"`
	IsServiceUser        bool                                       `json:"is_service_user"`
	IsBlocked            bool                                       `json:"is_blocked"`
	NonDeletable         bool                                       `json:"non_deletable"`
	LastLogin            time.Time                                  `json:"last_login"`
	Issued               string                                     `json:"issued"`
	PendingApproval      bool                                       `json:"pending_approval"`
	Password             string                                     `json:"password"`
	IntegrationReference integration_reference.IntegrationReference `json:"-"`
	// IdPID is the identity provider ID (connector ID) extracted from the Dex-encoded user ID.
	// This field is only populated when the user ID can be decoded from Dex's format.
	IdPID string `json:"idp_id,omitempty"`
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
	PATsG      []PersonalAccessToken           `json:"-" gorm:"foreignKey:UserID;references:id;constraint:OnDelete:CASCADE;"`
	// Blocked indicates whether the user is blocked. Blocked users can't use the system.
	Blocked bool
	// PendingApproval indicates whether the user requires approval before being activated
	PendingApproval bool
	// LastLogin is the last time the user logged in to IdP
	LastLogin *time.Time
	// CreatedAt records the time the user was created
	CreatedAt time.Time

	// Issued of the user
	Issued string `gorm:"default:api"`

	IntegrationReference integration_reference.IntegrationReference `gorm:"embedded;embeddedPrefix:integration_ref_"`

	Name  string `gorm:"default:''"`
	Email string `gorm:"default:''"`

	// Name and Email are encrypted at rest, so searches match these hashes of them.
	NameHash1 int64  `json:"-" gorm:"column:name_hash_1;->:false;<-"`
	NameHash2 int64  `json:"-" gorm:"column:name_hash_2;->:false;<-"`
	NameHash3 int64  `json:"-" gorm:"column:name_hash_3;->:false;<-"`
	EmailHash string `json:"-" gorm:"index;->:false;<-"`
}

// IsBlocked returns true if the user is blocked, false otherwise
func (u *User) IsBlocked() bool {
	return u.Blocked
}

func (u *User) LastDashboardLoginChanged(lastLogin time.Time) bool {
	return lastLogin.After(u.GetLastLogin()) && !u.GetLastLogin().IsZero()
}

// GetLastLogin returns the last login time of the user.
func (u *User) GetLastLogin() time.Time {
	if u.LastLogin != nil {
		return *u.LastLogin
	}
	return time.Time{}
}

// HasAdminPower returns true if the user has admin or owner roles, false otherwise
func (u *User) HasAdminPower() bool {
	return u.Role == UserRoleAdmin || u.Role == UserRoleOwner
}

// IsAdminOrServiceUser checks if the user has admin power or is a service user.
func (u *User) IsAdminOrServiceUser() bool {
	return u.HasAdminPower() || u.IsServiceUser
}

// IsRegularUser checks if the user is a regular user.
func (u *User) IsRegularUser() bool {
	return !u.HasAdminPower() && !u.IsServiceUser
}

// IsRestrictable checks whether a user is in a restrictable role.
func (u *User) IsRestrictable() bool {
	return u.Role == UserRoleUser || u.Role == UserRoleBillingAdmin || u.Role == UserRoleUsageViewer
}

// ToUserInfo converts a User object to a UserInfo object.
func (u *User) ToUserInfo(userData *idp.UserData) (*UserInfo, error) {
	autoGroups := u.AutoGroups
	if autoGroups == nil {
		autoGroups = []string{}
	}

	if userData == nil {

		name := u.Name
		if u.IsServiceUser {
			name = u.ServiceUserName
		}

		return &UserInfo{
			ID:              u.Id,
			Email:           u.Email,
			Name:            name,
			Role:            string(u.Role),
			AutoGroups:      u.AutoGroups,
			Status:          string(UserStatusActive),
			IsServiceUser:   u.IsServiceUser,
			IsBlocked:       u.Blocked,
			LastLogin:       u.GetLastLogin(),
			Issued:          u.Issued,
			PendingApproval: u.PendingApproval,
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
		ID:              u.Id,
		Email:           userData.Email,
		Name:            userData.Name,
		Role:            string(u.Role),
		AutoGroups:      autoGroups,
		Status:          string(userStatus),
		IsServiceUser:   u.IsServiceUser,
		IsBlocked:       u.Blocked,
		LastLogin:       u.GetLastLogin(),
		Issued:          u.Issued,
		PendingApproval: u.PendingApproval,
		Password:        userData.Password,
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
		PendingApproval:      u.PendingApproval,
		LastLogin:            u.LastLogin,
		CreatedAt:            u.CreatedAt,
		Issued:               u.Issued,
		IntegrationReference: u.IntegrationReference,
		Email:                u.Email,
		Name:                 u.Name,
	}
}

// NewUser creates a new user
func NewUser(id string, role UserRole, isServiceUser bool, nonDeletable bool, serviceUserName string, autoGroups []string, issued string, email string, name string) *User {
	return &User{
		Id:              id,
		Role:            role,
		IsServiceUser:   isServiceUser,
		NonDeletable:    nonDeletable,
		ServiceUserName: serviceUserName,
		AutoGroups:      autoGroups,
		Issued:          issued,
		CreatedAt:       time.Now().UTC(),
		Name:            name,
		Email:           email,
	}
}

// NewRegularUser creates a new user with role UserRoleUser
func NewRegularUser(id, email, name string) *User {
	return NewUser(id, UserRoleUser, false, false, "", []string{}, UserIssuedAPI, email, name)
}

// NewAdminUser creates a new user with role UserRoleAdmin
func NewAdminUser(id string) *User {
	return NewUser(id, UserRoleAdmin, false, false, "", []string{}, UserIssuedAPI, "", "")
}

// NewOwnerUser creates a new user with role UserRoleOwner
func NewOwnerUser(id string, email string, name string) *User {
	return NewUser(id, UserRoleOwner, false, false, "", []string{}, UserIssuedAPI, email, name)
}

// EncryptSensitiveData sets the search hashes, then encrypts Email and Name in place.
func (u *User) EncryptSensitiveData(enc *crypt.FieldEncrypt) error {
	u.SetSearchHashes(enc)
	if enc == nil {
		return nil
	}

	var err error
	if u.Email != "" {
		u.Email, err = enc.Encrypt(u.Email)
		if err != nil {
			return fmt.Errorf("encrypt email: %w", err)
		}
	}

	if u.Name != "" {
		u.Name, err = enc.Encrypt(u.Name)
		if err != nil {
			return fmt.Errorf("encrypt name: %w", err)
		}
	}

	return nil
}

func MaskEmail(email string) string {
	local, domain, found := strings.Cut(email, "@")
	if !found || local == "" || domain == "" {
		return ""
	}

	// Runes, not bytes, so a non-ASCII local part is not cut mid-character.
	runes := []rune(local)

	// Keeping the first two and the last needs a local part of at least four to
	// hide anything at all: at three or fewer those are the whole of it, and the
	// address would be recoverable in full from what is meant to conceal it.
	if len(runes) < 4 {
		return "****@" + domain
	}

	return string(runes[:2]) + "****" + string(runes[len(runes)-1]) + "@" + domain
}

// DecryptSensitiveData decrypts the user's sensitive fields (Email and Name) in place.
func (u *User) DecryptSensitiveData(enc *crypt.FieldEncrypt) error {
	if enc == nil {
		return nil
	}

	var err error
	if u.Email != "" {
		u.Email, err = enc.Decrypt(u.Email)
		if err != nil {
			return fmt.Errorf("decrypt email: %w", err)
		}
	}

	if u.Name != "" {
		u.Name, err = enc.Decrypt(u.Name)
		if err != nil {
			return fmt.Errorf("decrypt name: %w", err)
		}
	}

	return nil
}

// SetSearchHashes sets the search hashes from the plaintext name and email.
func (u *User) SetSearchHashes(enc *crypt.FieldEncrypt) {
	filter := NameFilter(enc, u.displayName())
	u.NameHash1, u.NameHash2, u.NameHash3 = filter[0], filter[1], filter[2]
	u.EmailHash = EmailSearchHash(enc, u.Email)
}

// MatchesName reports whether the user's name contains text, ignoring case.
func (u *User) MatchesName(text string) bool {
	return strings.Contains(strings.ToLower(u.displayName()), strings.ToLower(text))
}

func (u *User) displayName() string {
	if u.IsServiceUser {
		return u.ServiceUserName
	}
	return u.Name
}

// NameFilter returns a Bloom filter of the three-byte groups of text, ignoring case. The
// filter of a name covers the filter of any text the name contains.
func NameFilter(enc *crypt.FieldEncrypt, text string) [3]int64 {
	var filter [3]int64
	text = strings.ToLower(text)
	for i := 0; i+3 <= len(text); i++ {
		sum := searchHash(enc, text[i:i+3])
		for k := range 4 {
			bit := binary.BigEndian.Uint32(sum[4*k:]) % 192
			filter[bit/64] |= 1 << (bit % 64)
		}
	}
	return filter
}

// EmailSearchHash returns the hash of email, ignoring case and surrounding spaces.
func EmailSearchHash(enc *crypt.FieldEncrypt, email string) string {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return ""
	}
	return hex.EncodeToString(searchHash(enc, email))
}

// searchHash is unkeyed without encryption, as the values are then stored in plaintext.
func searchHash(enc *crypt.FieldEncrypt, text string) []byte {
	if enc == nil {
		sum := sha256.Sum256([]byte(text))
		return sum[:]
	}
	return enc.Hash([]byte(text))
}
