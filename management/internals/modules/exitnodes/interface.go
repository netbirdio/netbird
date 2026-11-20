package exitnodes

import (
	"context"
)

// Manager manages the exit nodes of an account.
type Manager interface {
	GetAllExitNodes(ctx context.Context, accountID, userID string) ([]*ExitNode, error)
	GetExitNode(ctx context.Context, accountID, userID string, exitNodeID ID) (*ExitNode, error)
	CreateExitNode(ctx context.Context, accountID, userID string, exitNode *ExitNode) (*ExitNode, error)
	UpdateExitNode(ctx context.Context, accountID, userID string, exitNode *ExitNode) (*ExitNode, error)
	DeleteExitNode(ctx context.Context, accountID, userID string, exitNodeID ID) error
}
