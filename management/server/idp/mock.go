package idp

import "context"

// MockIDP is a mock implementation of the IDP interface
type MockIDP struct {
	UpdateUserAppMetadataFunc func(ctx context.Context, userId string, appMetadata AppMetadata) error
	GetUserDataByIDFunc       func(ctx context.Context, userId string, appMetadata AppMetadata) (*UserData, error)
	GetAccountFunc            func(ctx context.Context, accountId string) ([]*UserData, error)
	GetAllAccountsFunc        func(ctx context.Context) (map[string][]*UserData, error)
	CreateUserFunc            func(ctx context.Context, email, name, accountID, invitedByEmail string) (*UserData, error)
	GetUserByEmailFunc        func(ctx context.Context, email string) ([]*UserData, error)
	InviteUserByIDFunc        func(ctx context.Context, userID string) error
	DeleteUserFunc            func(ctx context.Context, userID string) error
}

// UpdateUserAppMetadata is a mock implementation of the IDP interface UpdateUserAppMetadata method
func (m *MockIDP) UpdateUserAppMetadata(ctx context.Context, userId string, appMetadata AppMetadata) error {
	if m.UpdateUserAppMetadataFunc != nil {
		return m.UpdateUserAppMetadataFunc(ctx, userId, appMetadata)
	}
	return nil
}

// GetUserDataByID is a mock implementation of the IDP interface GetUserDataByID method
func (m *MockIDP) GetUserDataByID(ctx context.Context, userId string, appMetadata AppMetadata) (*UserData, error) {
	if m.GetUserDataByIDFunc != nil {
		return m.GetUserDataByIDFunc(ctx, userId, appMetadata)
	}
	return nil, nil
}

// GetAccount is a mock implementation of the IDP interface GetAccount method
func (m *MockIDP) GetAccount(ctx context.Context, accountId string) ([]*UserData, error) {
	if m.GetAccountFunc != nil {
		return m.GetAccountFunc(ctx, accountId)
	}
	return nil, nil
}

// GetAllAccounts is a mock implementation of the IDP interface GetAllAccounts method
func (m *MockIDP) GetAllAccounts(ctx context.Context) (map[string][]*UserData, error) {
	if m.GetAllAccountsFunc != nil {
		return m.GetAllAccountsFunc(ctx)
	}
	return nil, nil
}

// CreateUser is a mock implementation of the IDP interface CreateUser method
func (m *MockIDP) CreateUser(ctx context.Context, email, name, accountID, invitedByEmail string) (*UserData, error) {
	if m.CreateUserFunc != nil {
		return m.CreateUserFunc(ctx, email, name, accountID, invitedByEmail)
	}
	return nil, nil
}

// GetUserByEmail is a mock implementation of the IDP interface GetUserByEmail method
func (m *MockIDP) GetUserByEmail(ctx context.Context, email string) ([]*UserData, error) {
	if m.GetUserByEmailFunc != nil {
		return m.GetUserByEmailFunc(ctx, email)
	}
	return nil, nil
}

// InviteUserByID is a mock implementation of the IDP interface InviteUserByID method
func (m *MockIDP) InviteUserByID(ctx context.Context, userID string) error {
	if m.InviteUserByIDFunc != nil {
		return m.InviteUserByIDFunc(ctx, userID)
	}
	return nil
}

// DeleteUser is a mock implementation of the IDP interface DeleteUser method
func (m *MockIDP) DeleteUser(ctx context.Context, userID string) error {
	if m.DeleteUserFunc != nil {
		return m.DeleteUserFunc(ctx, userID)
	}
	return nil
}
