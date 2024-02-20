package system

import (
	"testing"

	log "github.com/sirupsen/logrus"
)

func Test_sysInfo(t *testing.T) {
	serialNum, err := sysNumber()
	if err != nil {
		t.Errorf("failed to get system serial number: %s", err)
	}

	prodName, err := sysProductName()
	if err != nil {
		t.Errorf("failed to get system product name: %s", err)
	}

	manufacturer, err := sysManufacturer()
	if err != nil {
		t.Errorf("failed to get system manufacturer: %s", err)
	}
	log.Infof("Windows sys info: %s, %s, %s", serialNum, prodName, manufacturer)
}
