package monotime

import (
	"testing"
	"time"
)

func BenchmarkMonotimeNow(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = Now()
	}
}

func BenchmarkTimeNow(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = time.Now()
	}
}
