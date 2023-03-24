package stdnet

import (
	"fmt"
	"testing"
)

func Test_parseInterfacesString(t *testing.T) {
	testData := []struct {
		name         string
		index        int
		mtu          int
		up           bool
		broadcast    bool
		loopBack     bool
		pointToPoint bool
		multicast    bool
		addr         string
	}{
		{"wlan0", 30, 1500, true, true, false, false, true, "10.1.10.131/24"},
		{"rmnet0", 30, 1500, true, true, false, false, true, "192.168.0.56/24"},
	}

	var exampleString string
	for _, d := range testData {
		exampleString = fmt.Sprintf("%s\n%s %d %d %t %t %t %t %t | %s", exampleString,
			d.name,
			d.index,
			d.mtu,
			d.up,
			d.broadcast,
			d.loopBack,
			d.pointToPoint,
			d.multicast,
			d.addr)
	}
	nets := parseInterfacesString(exampleString)
	if len(nets) == 0 {
		t.Fatalf("failed to parse interfaces")
	}

	for i, net := range nets {
		if net.MTU != testData[i].mtu {
			t.Errorf("invalid mtu: %d, expected: %d", net.MTU, testData[0].mtu)

		}

		if net.Interface.Name != testData[i].name {
			t.Errorf("invalid interface name: %s, expected: %s", net.Interface.Name, testData[i].name)
		}
	}
}
