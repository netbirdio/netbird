package version

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const httpAgent = "pkg/test"

func TestNewUpdate(t *testing.T) {
	version = "1.0.0"
	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "10.0.0")
	}))
	defer svr.Close()
	versionURL = svr.URL

	wg := &sync.WaitGroup{}
	wg.Add(1)

	onUpdate := false
	u := NewUpdateAndStart(httpAgent)
	defer u.StopWatch()
	u.SetOnUpdateListener(func() {
		onUpdate = true
		wg.Done()
	})

	waitTimeout(wg)
	if onUpdate != true {
		t.Errorf("update not found")
	}
}

func TestDoNotUpdate(t *testing.T) {
	version = "11.0.0"
	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "10.0.0")
	}))
	defer svr.Close()
	versionURL = svr.URL

	wg := &sync.WaitGroup{}
	wg.Add(1)

	onUpdate := false
	u := NewUpdateAndStart(httpAgent)
	defer u.StopWatch()
	u.SetOnUpdateListener(func() {
		onUpdate = true
		wg.Done()
	})

	waitTimeout(wg)
	if onUpdate == true {
		t.Errorf("invalid update")
	}
}

func TestDaemonUpdate(t *testing.T) {
	version = "11.0.0"
	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "11.0.0")
	}))
	defer svr.Close()
	versionURL = svr.URL

	wg := &sync.WaitGroup{}
	wg.Add(1)

	onUpdate := false
	u := NewUpdateAndStart(httpAgent)
	defer u.StopWatch()
	u.SetOnUpdateListener(func() {
		onUpdate = true
		wg.Done()
	})

	u.SetDaemonVersion("10.0.0")

	waitTimeout(wg)
	if onUpdate != true {
		t.Errorf("invalid daemon version check")
	}
}

func waitTimeout(wg *sync.WaitGroup) {
	c := make(chan struct{})
	go func() {
		wg.Wait()
		close(c)
	}()
	select {
	case <-c:
		return
	case <-time.After(time.Second):
		return
	}
}

// blockingVersionServer serves version requests that stay in flight until the client
// cancels them or the test ends. It reports each arrival on requested and each
// client-side cancellation on cancelled.
type blockingVersionServer struct {
	requests  atomic.Int32
	requested chan struct{}
	cancelled chan struct{}
}

func newBlockingVersionServer(t *testing.T) *blockingVersionServer {
	t.Helper()

	s := &blockingVersionServer{
		requested: make(chan struct{}, 16),
		cancelled: make(chan struct{}, 16),
	}
	release := make(chan struct{})
	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.requests.Add(1)
		s.requested <- struct{}{}
		select {
		case <-r.Context().Done():
			s.cancelled <- struct{}{}
		case <-release:
		}
	}))
	// Cleanups run in reverse order: unblock handlers first so Close does not wait on them.
	t.Cleanup(svr.Close)
	t.Cleanup(func() { close(release) })
	versionURL = svr.URL

	return s
}

// requireReturns fails the test if fn does not return within a few seconds.
func requireReturns(t *testing.T, name string, fn func()) {
	t.Helper()

	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s did not return", name)
	}
}

func TestUpdate_StartAndImmediateStop(t *testing.T) {
	newBlockingVersionServer(t)

	// The fetcher goroutine may or may not have started by the time StopWatch runs;
	// either way the race detector must stay quiet and the fetcher must not outlive
	// the stop.
	u := NewUpdateAndStart(httpAgent)
	requireReturns(t, "StopWatch", u.StopWatch)
	requireReturns(t, "StartFetcher after StopWatch", u.StartFetcher)
}

func TestUpdate_StopWatchBeforeFetcherRuns(t *testing.T) {
	srv := newBlockingVersionServer(t)

	u := NewUpdate(httpAgent)
	u.StopWatch()

	// A fetcher launched after StopWatch must exit on its own without fetching.
	requireReturns(t, "StartFetcher after StopWatch", u.StartFetcher)
	assert.Equal(t, int32(0), srv.requests.Load(), "a stopped fetcher must not query the version server")
}

func TestUpdate_StopWatchCancelsInFlightFetch(t *testing.T) {
	srv := newBlockingVersionServer(t)

	u := NewUpdateAndStart(httpAgent)
	select {
	case <-srv.requested:
	case <-time.After(5 * time.Second):
		t.Fatal("fetcher did not query the version server")
	}

	// The server holds the request open, so the fetcher is blocked in the HTTP call
	// when StopWatch runs and must be woken by cancelling the request.
	requireReturns(t, "StopWatch", u.StopWatch)
	select {
	case <-srv.cancelled:
	case <-time.After(5 * time.Second):
		t.Fatal("in-flight version request was not cancelled by StopWatch")
	}
}

func TestUpdate_StopWatchTwice(t *testing.T) {
	t.Run("not started", func(t *testing.T) {
		u := NewUpdate(httpAgent)
		requireReturns(t, "first StopWatch", u.StopWatch)
		requireReturns(t, "second StopWatch", u.StopWatch)
	})

	t.Run("running", func(t *testing.T) {
		srv := newBlockingVersionServer(t)

		u := NewUpdateAndStart(httpAgent)
		select {
		case <-srv.requested:
		case <-time.After(5 * time.Second):
			t.Fatal("fetcher did not query the version server")
		}
		requireReturns(t, "first StopWatch", u.StopWatch)
		requireReturns(t, "second StopWatch", u.StopWatch)
	})
}
