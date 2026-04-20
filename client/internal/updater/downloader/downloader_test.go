package downloader

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

const (
	retryDelay = 100 * time.Millisecond
)

func TestDownloadToFile_Success(t *testing.T) {
	// Create a test server that responds successfully
	content := "test file content"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(content))
	}))
	defer server.Close()

	// Create a temporary file for download
	tempDir := t.TempDir()
	dstFile := filepath.Join(tempDir, "downloaded.txt")

	// Download the file
	err := DownloadToFile(context.Background(), retryDelay, server.URL, dstFile)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Verify the file content
	data, err := os.ReadFile(dstFile)
	if err != nil {
		t.Fatalf("failed to read downloaded file: %v", err)
	}

	if string(data) != content {
		t.Errorf("expected content %q, got %q", content, string(data))
	}
}

func TestDownloadToFile_SuccessAfterRetry(t *testing.T) {
	content := "test file content after retry"
	var attemptCount atomic.Int32

	// Create a test server that fails on first attempt, succeeds on second
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempt := attemptCount.Add(1)
		if attempt == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("error"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(content))
	}))
	defer server.Close()

	// Create a temporary file for download
	tempDir := t.TempDir()
	dstFile := filepath.Join(tempDir, "downloaded.txt")

	// Download the file (should succeed after retry)
	if err := DownloadToFile(context.Background(), 10*time.Millisecond, server.URL, dstFile); err != nil {
		t.Fatalf("expected no error after retry, got: %v", err)
	}

	// Verify the file content
	data, err := os.ReadFile(dstFile)
	if err != nil {
		t.Fatalf("failed to read downloaded file: %v", err)
	}

	if string(data) != content {
		t.Errorf("expected content %q, got %q", content, string(data))
	}

	// Verify it took 2 attempts
	if attemptCount.Load() != 2 {
		t.Errorf("expected 2 attempts, got %d", attemptCount.Load())
	}
}

func TestDownloadToFile_FailsAfterRetry(t *testing.T) {
	var attemptCount atomic.Int32

	// Create a test server that always fails
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attemptCount.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("error"))
	}))
	defer server.Close()

	// Create a temporary file for download
	tempDir := t.TempDir()
	dstFile := filepath.Join(tempDir, "downloaded.txt")

	// Download the file (should fail after retry)
	if err := DownloadToFile(context.Background(), 10*time.Millisecond, server.URL, dstFile); err == nil {
		t.Fatal("expected error after retry, got nil")
	}

	// Verify it tried 2 times
	if attemptCount.Load() != 2 {
		t.Errorf("expected 2 attempts, got %d", attemptCount.Load())
	}
}

func TestDownloadToFile_ContextCancellationDuringRetry(t *testing.T) {
	var attemptCount atomic.Int32

	// Create a test server that always fails
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attemptCount.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	// Create a temporary file for download
	tempDir := t.TempDir()
	dstFile := filepath.Join(tempDir, "downloaded.txt")

	// Create a context that will be cancelled during retry delay
	ctx, cancel := context.WithCancel(context.Background())

	// Cancel after a short delay (during the retry sleep)
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	// Download the file (should fail due to context cancellation during retry)
	err := DownloadToFile(ctx, 1*time.Second, server.URL, dstFile)
	if err == nil {
		t.Fatal("expected error due to context cancellation, got nil")
	}

	// Should have only made 1 attempt (cancelled during retry delay)
	if attemptCount.Load() != 1 {
		t.Errorf("expected 1 attempt, got %d", attemptCount.Load())
	}
}

func TestDownloadToFile_InvalidURL(t *testing.T) {
	tempDir := t.TempDir()
	dstFile := filepath.Join(tempDir, "downloaded.txt")

	err := DownloadToFile(context.Background(), retryDelay, "://invalid-url", dstFile)
	if err == nil {
		t.Fatal("expected error for invalid URL, got nil")
	}
}

func TestDownloadToFile_InvalidDestination(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("test"))
	}))
	defer server.Close()

	// Use an invalid destination path
	err := DownloadToFile(context.Background(), retryDelay, server.URL, "/invalid/path/that/does/not/exist/file.txt")
	if err == nil {
		t.Fatal("expected error for invalid destination, got nil")
	}
}

func TestDownloadToFile_NoRetry(t *testing.T) {
	var attemptCount atomic.Int32

	// Create a test server that always fails
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attemptCount.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("error"))
	}))
	defer server.Close()

	// Create a temporary file for download
	tempDir := t.TempDir()
	dstFile := filepath.Join(tempDir, "downloaded.txt")

	// Download the file with retryDelay = 0 (should not retry)
	if err := DownloadToFile(context.Background(), 0, server.URL, dstFile); err == nil {
		t.Fatal("expected error, got nil")
	}

	// Verify it only made 1 attempt (no retry)
	if attemptCount.Load() != 1 {
		t.Errorf("expected 1 attempt, got %d", attemptCount.Load())
	}
}
