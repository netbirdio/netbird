package system

import (
	"testing"

	log "github.com/sirupsen/logrus"
)

func TestParsePlatformInfo(t *testing.T) {
	tests := []struct {
		name                              string
		output                            []byte
		wantSerialNumber, wantProductName string
		wantManufacturer                  string
	}{
		{
			name: "parses quoted Intel platform values",
			output: []byte(`
    | |   "IOPlatformSerialNumber" = "C02INTEL1234"
    | |   "model" = "MacBookPro15,1"
    | |   "manufacturer" = "Apple Inc."
`),
			wantSerialNumber: "C02INTEL1234",
			wantProductName:  "MacBookPro15,1",
			wantManufacturer: "Apple Inc.",
		},
		{
			name: "parses angle bracket Apple Silicon platform values",
			output: []byte(`
    | |   "IOPlatformSerialNumber" = <"F9APPLE1234">
    | |   "model" = <"Mac15,3">
    | |   "manufacturer" = <"Apple Inc.">
`),
			wantSerialNumber: "F9APPLE1234",
			wantProductName:  "Mac15,3",
			wantManufacturer: "Apple Inc.",
		},
		{
			name: "ignores unrelated keys",
			output: []byte(`
    | |   "IOPlatformSerialNumberBackup" = "wrong serial"
    | |   "ModelNumber" = "wrong model"
    | |   "device manufacturer" = "wrong manufacturer"
    | |   "IOPlatformSerialNumber" = "C02RIGHT1234"
    | |   "model" = "MacBookAir10,1"
    | |   "manufacturer" = "Apple Inc."
`),
			wantSerialNumber: "C02RIGHT1234",
			wantProductName:  "MacBookAir10,1",
			wantManufacturer: "Apple Inc.",
		},
		{
			name: "leaves missing platform values empty",
			output: []byte(`
    | |   "IOPlatformSerialNumber" = "C02ONLYSERIAL"
    | |   "board-id" = "Mac-1234567890ABCDEF"
`),
			wantSerialNumber: "C02ONLYSERIAL",
		},
		{
			name: "preserves equals signs in values",
			output: []byte(`
    | |   "IOPlatformSerialNumber" = "C02=SERIAL"
    | |   "model" = "Mac=Model"
    | |   "manufacturer" = "Apple=Inc."
`),
			wantSerialNumber: "C02=SERIAL",
			wantProductName:  "Mac=Model",
			wantManufacturer: "Apple=Inc.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSerialNumber, gotProductName, gotManufacturer := parsePlatformInfo(tt.output)

			if gotSerialNumber != tt.wantSerialNumber {
				t.Errorf("serial number = %q, want %q", gotSerialNumber, tt.wantSerialNumber)
			}
			if gotProductName != tt.wantProductName {
				t.Errorf("product name = %q, want %q", gotProductName, tt.wantProductName)
			}
			if gotManufacturer != tt.wantManufacturer {
				t.Errorf("manufacturer = %q, want %q", gotManufacturer, tt.wantManufacturer)
			}
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
