package client

import (
    "testing"
)

func TestGrpcClient_LastNetworkMapSerial_SetGet(t *testing.T) {
    c := &GrpcClient{}

    if got := c.getLastNetworkMapSerial(); got != 0 {
        t.Fatalf("initial serial should be 0, got %d", got)
    }

    c.setLastNetworkMapSerial(123)
    if got := c.getLastNetworkMapSerial(); got != 123 {
        t.Fatalf("serial after set should be 123, got %d", got)
    }

    // overwrite should work
    c.setLastNetworkMapSerial(5)
    if got := c.getLastNetworkMapSerial(); got != 5 {
        t.Fatalf("serial after overwrite should be 5, got %d", got)
    }
}


