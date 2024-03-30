package freebsd

import (
    "testing"
    "github.com/stretchr/testify/assert"
)

func TestParseIfconfigOutput(t *testing.T) {
    testOutput := `wg1: flags=8080<NOARP,MULTICAST> metric 0 mtu 1420
    options=80000<LINKSTATE>
    groups: wg
    nd6 options=109<PERFORMNUD,IFDISABLED,NO_DAD>`

    expected := &iface{
        Name:  "wg1",
        MTU:   1420,
        Group: "wg",
    }

    result, err := parseIfconfigOutput(testOutput)
    if err != nil {
        t.Errorf("Error parsing ifconfig output: %v", err)
        return
    }

    assert.Equal(t, expected.Name, result.Name, "Name should match")
    assert.Equal(t, expected.MTU, result.MTU, "MTU should match")
    assert.Equal(t, expected.Group, result.Group, "Group should match")
}

