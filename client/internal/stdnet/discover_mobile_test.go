package stdnet

import (
	"fmt"
	"testing"

	log "github.com/sirupsen/logrus"
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
		{"rmnet_data1", 30, 1500, true, true, false, false, true, "fec0::118c:faf7:8d97:3cb2/64"},
		{"rmnet_data2", 30, 1500, true, true, false, false, true, "fec0::118c:faf7:8d97:3cb2%rmnet2/64"},
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
	d := mobileIFaceDiscover{}
	nets := d.parseInterfacesString(exampleString)
	if len(nets) == 0 {
		t.Fatalf("failed to parse interfaces")
	}

	log.Printf("%d", len(nets))
	for i, net := range nets {
		if net.MTU != testData[i].mtu {
			t.Errorf("invalid mtu: %d, expected: %d", net.MTU, testData[0].mtu)

		}

		if net.Interface.Name != testData[i].name {
			t.Errorf("invalid interface name: %s, expected: %s", net.Interface.Name, testData[i].name)
		}

		addr, err := net.Addrs()
		if err != nil {
			t.Fatal(err)
		}

		if len(addr) == 0 {
			t.Errorf("invalid address parsing")
		}
		log.Printf("%v", addr)
		if addr[0].String() != testData[i].addr {
			t.Errorf("invalid address: %s, expected: %s", addr[0].String(), testData[i].addr)
		}
	}
}
