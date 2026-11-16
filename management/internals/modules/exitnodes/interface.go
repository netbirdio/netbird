package exitnodes

//go:generate go tool mockgen -package exitnodes -destination=interface_mock.go -source=./interface.go -build_flags=-mod=mod

import (
	"context"
)

// Manager manages the exit nodes of an account on behalf of a user.
type Manager interface {
	GetAllExitNodes(ctx context.Context, accountID, userID string) ([]*ExitNode, error)
	GetExitNode(ctx context.Context, accountID, userID, exitNodeID string) (*ExitNode, error)
	CreateExitNode(ctx context.Context, accountID, userID string, exitNode *ExitNode) (*ExitNode, error)
	UpdateExitNode(ctx context.Context, accountID, userID string, exitNode *ExitNode) (*ExitNode, error)
	DeleteExitNode(ctx context.Context, accountID, userID, exitNodeID string) error
}
