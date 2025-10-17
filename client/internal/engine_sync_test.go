package internal

import (
    "context"
    "testing"

    "golang.zx2c4.com/wireguard/wgctrl/wgtypes"

    "github.com/netbirdio/netbird/client/iface"
    "github.com/netbirdio/netbird/client/internal/peer"
    "github.com/netbirdio/netbird/shared/management/client"
    mgmtProto "github.com/netbirdio/netbird/shared/management/proto"
)

// Ensures handleSync exits early when SkipNetworkMapUpdate is true
func TestEngine_HandleSync_SkipNetworkMapUpdate(t *testing.T) {
    key, err := wgtypes.GeneratePrivateKey()
    if err != nil {
        t.Fatal(err)
    }

    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    engine := NewEngine(ctx, cancel, nil, &client.MockClient{}, nil, &EngineConfig{
        WgIfaceName:  "utun199",
        WgAddr:       "100.70.0.1/24",
        WgPrivateKey: key,
        WgPort:       33100,
        MTU:          iface.DefaultMTU,
    }, MobileDependency{}, peer.NewRecorder("https://mgm"), nil)
    engine.ctx = ctx

    // Precondition
    if engine.networkSerial != 0 {
        t.Fatalf("unexpected initial serial: %d", engine.networkSerial)
    }

    resp := &mgmtProto.SyncResponse{
        NetworkMap: &mgmtProto.NetworkMap{Serial: 42},
        SkipNetworkMapUpdate: true,
    }

    if err := engine.handleSync(resp); err != nil {
        t.Fatalf("handleSync returned error: %v", err)
    }

    if engine.networkSerial != 0 {
        t.Fatalf("networkSerial changed despite SkipNetworkMapUpdate; got %d, want 0", engine.networkSerial)
    }
}

// Ensures handleSync exits early when NetworkMap is nil
func TestEngine_HandleSync_NilNetworkMap(t *testing.T) {
    key, err := wgtypes.GeneratePrivateKey()
    if err != nil {
        t.Fatal(err)
    }

    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    engine := NewEngine(ctx, cancel, nil, &client.MockClient{}, nil, &EngineConfig{
        WgIfaceName:  "utun198",
        WgAddr:       "100.70.0.2/24",
        WgPrivateKey: key,
        WgPort:       33101,
        MTU:          iface.DefaultMTU,
    }, MobileDependency{}, peer.NewRecorder("https://mgm"), nil)
    engine.ctx = ctx

    resp := &mgmtProto.SyncResponse{NetworkMap: nil}

    if err := engine.handleSync(resp); err != nil {
        t.Fatalf("handleSync returned error: %v", err)
    }
}


