package system

import (
	log "github.com/sirupsen/logrus"
	"testing"
)

func Test_sysInfo(t *testing.T) {
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
