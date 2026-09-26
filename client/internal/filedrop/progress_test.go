package filedrop

import (
	"bytes"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProgressReader_ReportsEveryPercentAtMost(t *testing.T) {
	var reports []int64
	// Read one byte at a time out of a 1000 byte payload: without thinning that
	// would be 1000 reports for 100 percent worth of progress.
	reader := &progressReader{
		r:      bytes.NewReader(make([]byte, 1000)),
		total:  1000,
		report: func(sent int64) { reports = append(reports, sent) },
	}

	buf := make([]byte, 1)
	for {
		_, err := reader.Read(buf)
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
	}

	assert.LessOrEqual(t, len(reports), 100, "One report per percent at most")
	assert.Equal(t, int64(1000), reports[len(reports)-1], "The finished item must be reported")
}

func TestProgressReader_HoldsBackFasterThanTheInterval(t *testing.T) {
	reader := &progressReader{total: 1000, report: func(int64) {}}
	start := time.Now()

	reader.sent = 10
	require.True(t, reader.due(start), "The first percent goes through")

	reader.sent = 20
	assert.False(t, reader.due(start.Add(progressInterval/2)),
		"A percent arriving inside the interval waits")

	assert.True(t, reader.due(start.Add(progressInterval)),
		"The same percent goes through once the interval has passed")
}

func TestProgressReader_ReportsTheLastByteWhateverTheInterval(t *testing.T) {
	reader := &progressReader{total: 1000, report: func(int64) {}}
	start := time.Now()

	reader.sent = 500
	require.True(t, reader.due(start))

	reader.sent = 1000
	assert.True(t, reader.due(start.Add(time.Millisecond)),
		"A finished item is never held back by the interval")
}

func TestProgressReader_ReportsEveryReadWithoutASize(t *testing.T) {
	// A payload of unknown size has no percent to thin against, so every read
	// is worth reporting rather than none.
	reader := &progressReader{total: 0, report: func(int64) {}}

	reader.sent = 1
	assert.True(t, reader.due(time.Now()))
}

func TestAcceptedReader_StopsOnceTheOfferIsWithdrawn(t *testing.T) {
	accepted := true
	reader := &acceptedReader{
		r:        bytes.NewReader(make([]byte, 1024)),
		accepted: func() bool { return accepted },
		// Backdated so the very first read checks rather than waiting out the
		// interval.
		last: time.Now().Add(-progressInterval),
	}

	buf := make([]byte, 128)
	n, err := reader.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, 128, n, "An accepted offer reads normally")

	accepted = false
	reader.last = time.Now().Add(-progressInterval)

	_, err = reader.Read(buf)
	assert.ErrorIs(t, err, ErrNotAccepted, "A withdrawn offer stops the copy")
}

func TestAcceptedReader_ChecksNoMoreOftenThanTheInterval(t *testing.T) {
	checks := 0
	reader := &acceptedReader{
		r:        bytes.NewReader(make([]byte, 4096)),
		accepted: func() bool { checks++; return true },
	}

	buf := make([]byte, 1)
	for range 32 {
		_, err := reader.Read(buf)
		require.NoError(t, err)
	}

	assert.LessOrEqual(t, checks, 1, "The offer store is not locked once per read")
}
