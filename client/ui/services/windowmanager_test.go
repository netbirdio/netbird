//go:build !android && !ios && !freebsd && !js

package services

import (
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/wailsapp/wails/v3/pkg/application"
)

func newTestWindowManager() *WindowManager {
	return &WindowManager{
		creating:   map[string]bool{},
		pendingOps: map[string][]windowOp{},
	}
}

func waitDone(t *testing.T, done <-chan struct{}, msg string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal(msg)
	}
}

func TestWithWindowReusesExistingWindow(t *testing.T) {
	s := newTestWindowManager()
	existing := &application.WebviewWindow{}
	slot := existing
	factoryCalls := 0
	var got *application.WebviewWindow
	created := true
	s.withWindow(windowMain, &slot, func() *application.WebviewWindow {
		factoryCalls++
		return &application.WebviewWindow{}
	}, func(w *application.WebviewWindow, c bool) {
		got, created = w, c
	})
	require.Equal(t, 0, factoryCalls)
	require.Same(t, existing, got)
	require.False(t, created)
}

func TestWithWindowNilFactoryWithoutWindowSkipsOp(t *testing.T) {
	s := newTestWindowManager()
	var slot *application.WebviewWindow
	opCalls := 0
	s.withWindow(windowMain, &slot, nil, func(*application.WebviewWindow, bool) {
		opCalls++
	})
	require.Equal(t, 0, opCalls)
	require.Nil(t, slot)
}

func TestWithWindowReentrantCallDuringCreationIsQueued(t *testing.T) {
	s := newTestWindowManager()
	var slot *application.WebviewWindow
	factoryCalls := 0
	var order []string
	var factory func() *application.WebviewWindow
	factory = func() *application.WebviewWindow {
		factoryCalls++
		// Simulates the Windows message pump re-entering the tray click handler
		// while WebView2 is still initialising the window being created.
		s.withWindow(windowMain, &slot, factory, func(_ *application.WebviewWindow, created bool) {
			order = append(order, fmt.Sprintf("reentrant:%v", created))
		})
		return &application.WebviewWindow{}
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.withWindow(windowMain, &slot, factory, func(_ *application.WebviewWindow, created bool) {
			order = append(order, fmt.Sprintf("outer:%v", created))
		})
	}()
	waitDone(t, done, "withWindow deadlocked on a re-entrant call during creation")

	require.Equal(t, 1, factoryCalls)
	require.Equal(t, []string{"outer:true", "reentrant:false"}, order)
	require.NotNil(t, slot)
	require.Empty(t, s.creating)
	require.Empty(t, s.pendingOps)
}

func TestWithWindowConcurrentCallersShareOneCreation(t *testing.T) {
	s := newTestWindowManager()
	var slot *application.WebviewWindow
	factoryEntered := make(chan struct{})
	release := make(chan struct{})
	var factoryCalls, opCalls atomic.Int32
	factory := func() *application.WebviewWindow {
		factoryCalls.Add(1)
		close(factoryEntered)
		<-release
		return &application.WebviewWindow{}
	}
	op := func(*application.WebviewWindow, bool) { opCalls.Add(1) }

	first := make(chan struct{})
	go func() {
		defer close(first)
		s.withWindow(windowSettings, &slot, factory, op)
	}()
	<-factoryEntered

	second := make(chan struct{})
	go func() {
		defer close(second)
		s.withWindow(windowSettings, &slot, factory, op)
	}()
	waitDone(t, second, "second caller blocked while the window was being created")
	require.Equal(t, int32(0), opCalls.Load())

	close(release)
	waitDone(t, first, "creator did not finish")

	require.Equal(t, int32(1), factoryCalls.Load())
	require.Equal(t, int32(2), opCalls.Load())
	require.NotNil(t, slot)
}

func TestWithWindowOpsQueuedDuringCreationRunInArrivalOrder(t *testing.T) {
	s := newTestWindowManager()
	var slot *application.WebviewWindow
	var order []string
	record := func(label string) windowOp {
		return func(_ *application.WebviewWindow, created bool) {
			order = append(order, fmt.Sprintf("%s:%v", label, created))
		}
	}
	var factory func() *application.WebviewWindow
	factory = func() *application.WebviewWindow {
		s.withWindow(windowMain, &slot, factory, func(w *application.WebviewWindow, created bool) {
			record("a")(w, created)
			// Arrives while the creator is still draining the queue: it must not
			// jump ahead of "b" through the existing-window fast path.
			s.withWindow(windowMain, &slot, factory, record("c"))
		})
		s.withWindow(windowMain, &slot, factory, record("b"))
		return &application.WebviewWindow{}
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.withWindow(windowMain, &slot, factory, record("outer"))
	}()
	waitDone(t, done, "withWindow deadlocked while draining queued operations")

	require.Equal(t, []string{"outer:true", "a:false", "b:false", "c:false"}, order)
	require.Empty(t, s.creating)
	require.Empty(t, s.pendingOps)
}

func TestWithWindowFactoryPanicReleasesCreation(t *testing.T) {
	s := newTestWindowManager()
	var slot *application.WebviewWindow
	func() {
		defer func() { require.NotNil(t, recover()) }()
		s.withWindow(windowMain, &slot, func() *application.WebviewWindow {
			panic("factory failed")
		}, func(*application.WebviewWindow, bool) {})
	}()
	require.Empty(t, s.creating)
	require.Empty(t, s.pendingOps)
	require.Nil(t, slot)

	created := false
	s.withWindow(windowMain, &slot, func() *application.WebviewWindow {
		return &application.WebviewWindow{}
	}, func(_ *application.WebviewWindow, c bool) {
		created = c
	})
	require.True(t, created)
	require.NotNil(t, slot)
}

func TestWithWindowNilFromFactoryReleasesCreation(t *testing.T) {
	s := newTestWindowManager()
	var slot *application.WebviewWindow
	opCalls := 0
	s.withWindow(windowMain, &slot, func() *application.WebviewWindow {
		return nil
	}, func(*application.WebviewWindow, bool) {
		opCalls++
	})
	require.Equal(t, 0, opCalls)
	require.Empty(t, s.creating)
	require.Nil(t, slot)
}
