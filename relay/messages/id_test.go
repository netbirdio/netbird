package messages

import (
	"testing"
)

func TestHashID(t *testing.T) {
	hashedID, hashedStringId := HashID("alice")
	enc := HashIDToString(hashedID)
	if enc != hashedStringId {
		t.Errorf("expected %s, got %s", hashedStringId, enc)
	}
}
