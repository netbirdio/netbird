package client

import (
	"github.com/wiretrustee/wiretrustee/management/proto"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"io"
)

type Client interface {
	io.Closer
	Sync(msgHandler func(msg *proto.SyncResponse) error) error
	GetServerPublicKey() (*wgtypes.Key, error)
	Register(serverKey wgtypes.Key, setupKey string) (*proto.LoginResponse, error)
	Login(serverKey wgtypes.Key) (*proto.LoginResponse, error)
}
