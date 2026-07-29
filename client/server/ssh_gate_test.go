package server

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal/ipcauth"
)

func ctxWithIdentity(id ipcauth.Identity) context.Context {
	return peer.NewContext(context.Background(), &peer.Peer{AuthInfo: ipcauth.AuthInfo{Identity: id}})
}

func boolPtr(b bool) *bool { return &b }

func TestRequirePrivilegedForDangerousSSH(t *testing.T) {
	root := ipcauth.Identity{UID: 0}
	user := ipcauth.Identity{UID: 1000}

	tests := []struct {
		name           string
		ctx            context.Context
		enableSSHRoot  *bool
		disableSSHAuth *bool
		wantDenied     bool
	}{
		{"no flags, no identity", context.Background(), nil, nil, false},
		{"flags false, non-priv", ctxWithIdentity(user), boolPtr(false), boolPtr(false), false},
		{"enableSSHRoot by root", ctxWithIdentity(root), boolPtr(true), nil, false},
		{"enableSSHRoot by non-priv", ctxWithIdentity(user), boolPtr(true), nil, true},
		{"disableSSHAuth by non-priv", ctxWithIdentity(user), nil, boolPtr(true), true},
		{"enableSSHRoot no identity (fail closed)", context.Background(), boolPtr(true), nil, true},
		{"both by root", ctxWithIdentity(root), boolPtr(true), boolPtr(true), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := requirePrivilegedForDangerousSSH(tt.ctx, tt.enableSSHRoot, tt.disableSSHAuth)
			if tt.wantDenied {
				assert.Error(t, err)
				assert.Equal(t, codes.PermissionDenied, gstatus.Code(err))
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
