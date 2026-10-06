package filedrop

import (
	"io"
	"time"
)

// progressInterval is the floor between two progress reports of one item. A
// percent of a large file can pass in a millisecond, and every report ends up
// writing history and waking the UI, so the rate is capped regardless.
const progressInterval = 200 * time.Millisecond

// progressReader reports how much of an item has moved as it is read. Reports
// are thinned to one per whole percent, and to one per progressInterval when
// the bytes outrun even that; the last one always goes through so a transfer
// never stops a tick short of done.
type progressReader struct {
	r       io.Reader
	sent    int64
	total   int64
	report  func(sent int64)
	percent int
	last    time.Time
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	if n == 0 {
		return n, err
	}

	p.sent += int64(n)
	if p.due(time.Now()) {
		p.report(p.sent)
	}
	return n, err
}

// due decides whether the reader has moved enough, and waited long enough, to
// be worth another report.
func (p *progressReader) due(now time.Time) bool {
	if p.total <= 0 || p.sent >= p.total {
		return true
	}

	percent := int(p.sent * 100 / p.total)
	if percent == p.percent {
		return false
	}
	if !p.last.IsZero() && now.Sub(p.last) < progressInterval {
		return false
	}

	p.percent = percent
	p.last = now
	return true
}
