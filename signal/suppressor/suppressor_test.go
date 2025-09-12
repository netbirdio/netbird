package suppressor

import (
	"testing"
	"time"
)

func TestSuppressor_PackageReceived(t *testing.T) {
	destID := PeerID("remote")
	s, _ := NewSuppressor(&Opts{RepetitionThreshold: 3})

	// Define sequence with base deltas (s ±10% tolerance)
	deltas := []time.Duration{
		800 * time.Millisecond,
		1600 * time.Millisecond,
		3200 * time.Millisecond,
		6400 * time.Millisecond,
		10 * time.Second,
		10 * time.Second,
		10 * time.Second,
		10 * time.Second, // should be suppressed
		10 * time.Second,
		10 * time.Second,
	}
	sizes := []int{
		100,
		100,
		100,
		100,
		100,
		100,
		100,
		100,
		100,
		100,
	}

	expected := []bool{
		true,
		true,
		true,
		true,
		true,
		true,
		true,
		false,
		false,
		false,
	}

	// Apply ±10% tolerance
	times := make([]time.Time, len(deltas)+1)
	times[0] = time.Now()
	for i, d := range deltas {
		// ±10% randomization
		offset := d / 10
		times[i+1] = times[i].Add(d + offset) // for deterministic test, using +10%
	}

	for i, arrival := range times[1:] {
		allowed := s.PackageReceived(destID, sizes[i], arrival)
		if allowed != expected[i] {
			t.Errorf("Packet %d at %v: expected allowed=%v, got %v", i+1, arrival.Sub(times[0]), expected[i], allowed)
		}
		t.Logf("Packet %d at %v allowed: %v", i+1, arrival.Sub(times[0]), allowed)
	}
}

func TestSuppressor_PackageReceivedReset(t *testing.T) {
	destID := PeerID("remote")
	s, _ := NewSuppressor(&Opts{RepetitionThreshold: 5})

	// Define sequence with base deltas (s ±10% tolerance)
	deltas := []time.Duration{
		800 * time.Millisecond,
		1600 * time.Millisecond,
		3200 * time.Millisecond,
		6400 * time.Millisecond,
		10 * time.Second,
		10 * time.Second,
		10 * time.Second,
		10 * time.Second,
		10 * time.Second,
		10 * time.Second,
		10 * time.Second,
		10 * time.Second,
		10 * time.Second,
		10 * time.Second,
		10 * time.Second,
	}
	sizes := []int{
		100,
		100,
		100,
		100,
		100,
		100,
		100,
		100,
		100,
		100,
		100,
		50,
		100,
		100,
		100,
	}

	expected := []bool{
		true,
		true,
		true,
		true,
		true,
		true,
		true,
		true,
		true,
		false,
		false,
		true,
		true,
		true,
		true,
	}

	// Apply ±10% tolerance
	times := make([]time.Time, len(deltas)+1)
	times[0] = time.Now()
	for i, d := range deltas {
		// ±10% randomization
		offset := d / 10
		times[i+1] = times[i].Add(d + offset) // for deterministic test, using +10%
	}

	for i, arrival := range times[1:] {
		allowed := s.PackageReceived(destID, sizes[i], arrival)
		if allowed != expected[i] {
			t.Errorf("Packet %d at %v: expected allowed=%v, got %v", i+1, arrival.Sub(times[0]), expected[i], allowed)
		}
		t.Logf("Packet %d at %v allowed: %v", i+1, arrival.Sub(times[0]), allowed)
	}
}
