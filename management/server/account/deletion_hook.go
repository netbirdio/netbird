package account

import "context"

// DeletionHook runs when an account is deleted, after the caller's permission to delete
// it has been checked and before any of its users or data are removed. It lets code that
// keeps per-account state outside the store tear that state down while the account still
// exists.
//
// A hook that returns an error aborts the deletion and the account is kept. The caller
// sees the error, so a hook that wants a specific response returns a status error. A
// retried deletion runs every hook again, and a later step can still fail after the hooks
// succeed, so a hook must be idempotent and must tolerate the account surviving it.
type DeletionHook func(ctx context.Context, accountID string) error
