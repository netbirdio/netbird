package idp

// MockIDP is a mock implementation of the IDP interface
type MockIDP struct {
	UpdateUserAppMetadataFunc func(userId string, appMetadata AppMetadata) error
	GetUserDataByIDFunc       func(userId string, appMetadata AppMetadata) (*UserData, error)
	GetAccountFunc            func(accountId string) ([]*UserData, error)
	GetAllAccountsFunc        func() (map[string][]*UserData, error)
	CreateUserFunc            func(email, name, accountID, invitedByEmail string) (*UserData, error)
	GetUserByEmailFunc        func(email string) ([]*UserData, error)
	InviteUserByIDFunc        func(userID string) error
	DeleteUserFunc            func(userID string) error
}

// UpdateUserAppMetadata is a mock implementation of the IDP interface UpdateUserAppMetadata method
func (m *MockIDP) UpdateUserAppMetadata(userId string, appMetadata AppMetadata) error {
	if m.UpdateUserAppMetadataFunc != nil {
		return m.UpdateUserAppMetadataFunc(userId, appMetadata)
	}
	return nil
}

// GetUserDataByID is a mock implementation of the IDP interface GetUserDataByID method
func (m *MockIDP) GetUserDataByID(userId string, appMetadata AppMetadata) (*UserData, error) {
	if m.GetUserDataByIDFunc != nil {
		return m.GetUserDataByIDFunc(userId, appMetadata)
	}
	return nil, nil
}

// GetAccount is a mock implementation of the IDP interface GetAccount method
func (m *MockIDP) GetAccount(accountId string) ([]*UserData, error) {
	if m.GetAccountFunc != nil {
		return m.GetAccountFunc(accountId)
	}
	return nil, nil
}

// GetAllAccounts is a mock implementation of the IDP interface GetAllAccounts method
func (m *MockIDP) GetAllAccounts() (map[string][]*UserData, error) {
	if m.GetAllAccountsFunc != nil {
		return m.GetAllAccountsFunc()
	}
	return nil, nil
}

// CreateUser is a mock implementation of the IDP interface CreateUser method
func (m *MockIDP) CreateUser(email, name, accountID, invitedByEmail string) (*UserData, error) {
	if m.CreateUserFunc != nil {
		return m.CreateUserFunc(email, name, accountID, invitedByEmail)
	}
	return nil, nil
}

// GetUserByEmail is a mock implementation of the IDP interface GetUserByEmail method
func (m *MockIDP) GetUserByEmail(email string) ([]*UserData, error) {
	if m.GetUserByEmailFunc != nil {
		return m.GetUserByEmailFunc(email)
	}
	return nil, nil
}

// InviteUserByID is a mock implementation of the IDP interface InviteUserByID method
func (m *MockIDP) InviteUserByID(userID string) error {
	if m.InviteUserByIDFunc != nil {
		return m.InviteUserByIDFunc(userID)
	}
	return nil
}

// DeleteUser is a mock implementation of the IDP interface DeleteUser method
func (m *MockIDP) DeleteUser(userID string) error {
	if m.DeleteUserFunc != nil {
		return m.DeleteUserFunc(userID)
	}
	return nil
}
