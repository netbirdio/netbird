package idp

import "context"

// MockIDP is a mock implementation of the IDP interface
type MockIDP struct {
	CreateUserFunc      func(ctx context.Context, email, name string) (*UserData, error)
	GetUserDataByIDFunc func(ctx context.Context, userId string) (*UserData, error)
	GetUserByEmailFunc  func(ctx context.Context, email string) ([]*UserData, error)
	GetAllUsersFunc     func(ctx context.Context) ([]*UserData, error)
	InviteUserByIDFunc  func(ctx context.Context, userID string) error
	DeleteUserFunc      func(ctx context.Context, userID string) error
}

// CreateUser is a mock implementation of the IDP interface CreateUser method
func (m *MockIDP) CreateUser(ctx context.Context, email, name string) (*UserData, error) {
	if m.CreateUserFunc != nil {
		return m.CreateUserFunc(ctx, email, name)
	}
	return nil, nil
}

// GetUserDataByID is a mock implementation of the IDP interface GetUserDataByID method
func (m *MockIDP) GetUserDataByID(ctx context.Context, userId string) (*UserData, error) {
	if m.GetUserDataByIDFunc != nil {
		return m.GetUserDataByIDFunc(ctx, userId)
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

// GetAllUsers is a mock implementation of the IDP interface GetAllUsers method
func (m *MockIDP) GetAllUsers(ctx context.Context) ([]*UserData, error) {
	if m.GetAllUsersFunc != nil {
		return m.GetAllUsersFunc(ctx)
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
