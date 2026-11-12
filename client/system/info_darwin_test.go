package system

import (
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestParseIoRegUUID(t *testing.T) {
	const device = `+-o J314sAP  <class IOPlatformExpertDevice, id 0x100000214, registered, matched, active, busy 0 (2 ms), retain 34>
    {
      "IOPlatformSerialNumber" = "C02XL0GZJGH5"
      "IOPlatformUUID" = "4C4C4544-0042-3510-8051-B4C04F4E3332"
      "IOPlatformUUIDHint" = "00000000-0000-0000-0000-000000000001"
    }`

	tests := []struct {
		name string
		out  string
		want string
	}{
		{name: "device output", out: device, want: "4C4C4544-0042-3510-8051-B4C04F4E3332"},
		{name: "empty output", out: "", want: ""},
		{name: "key absent", out: `      "IOPlatformSerialNumber" = "C02XL0GZJGH5"`, want: ""},
		{name: "similar key only", out: `      "IOPlatformUUIDHint" = "4C4C4544-0042-3510-8051-B4C04F4E3332"`, want: ""},
		{name: "no separator", out: `      "IOPlatformUUID" "4C4C4544-0042-3510-8051-B4C04F4E3332"`, want: ""},
		{name: "extra separator", out: `      "IOPlatformUUID" = "4C4C4544=0042" = "x"`, want: ""},
		{name: "unquoted value", out: `      "IOPlatformUUID" = 4C4C4544-0042-3510-8051-B4C04F4E3332`, want: "4C4C4544-0042-3510-8051-B4C04F4E3332"},
		{name: "placeholder", out: `      "IOPlatformUUID" = "00000000-0000-0000-0000-000000000000"`, want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, parseIoRegUUID(tt.out), "parsed IOPlatformUUID")
		})
	}
}

func Test_sysInfoMac(t *testing.T) {
	t.Skip("skipping darwin test")
	serialNum, prodName, manufacturer := sysInfo()
	if serialNum == "" {
		t.Errorf("serialNum is empty")
	}

	if prodName == "" {
		t.Errorf("prodName is empty")
	}

	if manufacturer == "" {
		t.Errorf("manufacturer is empty")
	}
	log.Infof("Mac sys info: %s, %s, %s", serialNum, prodName, manufacturer)
}
