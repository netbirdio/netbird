package android

import "testing"

func TestDNSList_Get(t *testing.T) {
	l := DNSList{
		items: make([]string, 1),
	}

	_, err := l.Get(0)
	if err != nil {
		t.Errorf("invalid error: %s", err)
	}

	_, err = l.Get(-1)
	if err == nil {
		t.Errorf("expected error but got nil")
	}

	_, err = l.Get(1)
	if err == nil {
		t.Errorf("expected error but got nil")
	}
}
