// Code generated by MockGen. DO NOT EDIT.
// Source: ./manager.go

// Package permissions is a generated GoMock package.
package permissions

import (
	context "context"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	modules "github.com/netbirdio/netbird/management/server/permissions/modules"
	operations "github.com/netbirdio/netbird/management/server/permissions/operations"
	roles "github.com/netbirdio/netbird/management/server/permissions/roles"
	types "github.com/netbirdio/netbird/management/server/types"
)

// MockManager is a mock of Manager interface.
type MockManager struct {
	ctrl     *gomock.Controller
	recorder *MockManagerMockRecorder
}

// MockManagerMockRecorder is the mock recorder for MockManager.
type MockManagerMockRecorder struct {
	mock *MockManager
}

// NewMockManager creates a new mock instance.
func NewMockManager(ctrl *gomock.Controller) *MockManager {
	mock := &MockManager{ctrl: ctrl}
	mock.recorder = &MockManagerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockManager) EXPECT() *MockManagerMockRecorder {
	return m.recorder
}

// GetPermissions mocks base method.
func (m *MockManager) GetPermissions(ctx context.Context) map[types.UserRole]roles.RolePermissions {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetPermissions", ctx)
	ret0, _ := ret[0].(map[types.UserRole]roles.RolePermissions)
	return ret0
}

// GetPermissions indicates an expected call of GetPermissions.
func (mr *MockManagerMockRecorder) GetPermissions(ctx interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetPermissions", reflect.TypeOf((*MockManager)(nil).GetPermissions), ctx)
}

// GetRolePermissions mocks base method.
func (m *MockManager) GetRolePermissions(ctx context.Context, role types.UserRole) (roles.RolePermissions, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetRolePermissions", ctx, role)
	ret0, _ := ret[0].(roles.RolePermissions)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetRolePermissions indicates an expected call of GetRolePermissions.
func (mr *MockManagerMockRecorder) GetRolePermissions(ctx, role interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRolePermissions", reflect.TypeOf((*MockManager)(nil).GetRolePermissions), ctx, role)
}

// ValidateAccountAccess mocks base method.
func (m *MockManager) ValidateAccountAccess(ctx context.Context, accountID string, user *types.User, allowOwnerAndAdmin bool) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ValidateAccountAccess", ctx, accountID, user, allowOwnerAndAdmin)
	ret0, _ := ret[0].(error)
	return ret0
}

// ValidateAccountAccess indicates an expected call of ValidateAccountAccess.
func (mr *MockManagerMockRecorder) ValidateAccountAccess(ctx, accountID, user, allowOwnerAndAdmin interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ValidateAccountAccess", reflect.TypeOf((*MockManager)(nil).ValidateAccountAccess), ctx, accountID, user, allowOwnerAndAdmin)
}

// ValidateRoleModuleAccess mocks base method.
func (m *MockManager) ValidateRoleModuleAccess(ctx context.Context, accountID string, role roles.RolePermissions, module modules.Module, operation operations.Operation) bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ValidateRoleModuleAccess", ctx, accountID, role, module, operation)
	ret0, _ := ret[0].(bool)
	return ret0
}

// ValidateRoleModuleAccess indicates an expected call of ValidateRoleModuleAccess.
func (mr *MockManagerMockRecorder) ValidateRoleModuleAccess(ctx, accountID, role, module, operation interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ValidateRoleModuleAccess", reflect.TypeOf((*MockManager)(nil).ValidateRoleModuleAccess), ctx, accountID, role, module, operation)
}

// ValidateUserPermissions mocks base method.
func (m *MockManager) ValidateUserPermissions(ctx context.Context, accountID, userID string, module modules.Module, operation operations.Operation) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ValidateUserPermissions", ctx, accountID, userID, module, operation)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ValidateUserPermissions indicates an expected call of ValidateUserPermissions.
func (mr *MockManagerMockRecorder) ValidateUserPermissions(ctx, accountID, userID, module, operation interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ValidateUserPermissions", reflect.TypeOf((*MockManager)(nil).ValidateUserPermissions), ctx, accountID, userID, module, operation)
}
