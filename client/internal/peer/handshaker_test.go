package peer

import (
	"testing"
)

func TestHandshaker_AddRemoveICEListener(t *testing.T) {
	h := &Handshaker{}
	listener := func(o *OfferAnswer) {}

	h.AddICEListener(listener)
	if h.iceListener == nil {
		t.Fatal("iceListener should be set after AddICEListener")
	}

	h.RemoveICEListener()
	if h.iceListener != nil {
		t.Fatal("iceListener should be nil after RemoveICEListener")
	}

	// Idempotency: removing again is a no-op.
	h.RemoveICEListener()
	if h.iceListener != nil {
		t.Fatal("RemoveICEListener should be idempotent")
	}

	// Re-add works.
	h.AddICEListener(listener)
	if h.iceListener == nil {
		t.Fatal("re-adding the listener should work")
	}
}

func TestHandshaker_readICEListener(t *testing.T) {
	h := &Handshaker{}
	if got := h.readICEListener(); got != nil {
		t.Fatal("readICEListener on empty Handshaker should return nil")
	}

	listener := func(o *OfferAnswer) {}
	h.AddICEListener(listener)
	if got := h.readICEListener(); got == nil {
		t.Fatal("readICEListener after AddICEListener should return non-nil")
	}

	h.RemoveICEListener()
	if got := h.readICEListener(); got != nil {
		t.Fatal("readICEListener after RemoveICEListener should return nil")
	}
}
