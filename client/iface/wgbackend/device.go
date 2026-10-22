package wgbackend

import "github.com/netbirdio/wireguard-go/device"

type (
	Device            = device.Device
	NoisePresharedKey = device.NoisePresharedKey
	NoisePrivateKey   = device.NoisePrivateKey
	NoisePublicKey    = device.NoisePublicKey
	Peer              = device.Peer
	PeerConfig        = device.PeerConfig
)

const (
	LogLevelSilent  = device.LogLevelSilent
	LogLevelVerbose = device.LogLevelVerbose
)

var (
	NewDevice                     = device.NewDevice
	NewLogger                     = device.NewLogger
	SetMaxBatchSizeOverride       = device.SetMaxBatchSizeOverride
	SetPreallocatedBuffersPerPool = device.SetPreallocatedBuffersPerPool
)
