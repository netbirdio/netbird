package messages

import (
	"encoding/binary"
	"testing"

	log "github.com/sirupsen/logrus"
)

func TestHashID(t *testing.T) {
	hashedID, hashedStringId := HashID("abc")
	enc := HashIDToString(hashedID)
	if enc != hashedStringId {
		t.Errorf("expected %s, got %s", hashedStringId, enc)
	}

	var magicHeader uint32 = 0x2112A442 // size 4 byte

	msg := make([]byte, 4)
	binary.BigEndian.PutUint32(msg, magicHeader)

	magicHeader2 := []byte{0x21, 0x12, 0xA4, 0x42}

	log.Infof("msg: %v, %v", msg, magicHeader2)

}
