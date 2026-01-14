package reverseproxy

import (
	"encoding/json"
	"sync"
	"testing"
	"time"
)

func TestLogWriter_Write(t *testing.T) {
	// Create a channel to receive callback data
	callbackChan := make(chan *RequestData, 1)
	var callbackMu sync.Mutex
	var callbackCalled bool

	// Register a test callback
	testServiceID := "test-service"
	RegisterCallback(testServiceID, func(data *RequestData) {
		callbackMu.Lock()
		callbackCalled = true
		callbackMu.Unlock()
		callbackChan <- data
	})
	defer UnregisterCallback(testServiceID)

	// Create a log writer
	writer := NewLogWriter(testServiceID)

	// Create a sample Caddy access log entry (matching the structure from your logs)
	logEntry := map[string]interface{}{
		"level":  "info",
		"ts":     1768352053.7900746,
		"logger": "http.log.access",
		"msg":    "handled request",
		"request": map[string]interface{}{
			"remote_ip":   "::1",
			"remote_port": "51972",
			"client_ip":   "::1",
			"proto":       "HTTP/1.1",
			"method":      "GET",
			"host":        "test.netbird.io:54321",
			"uri":         "/test/path",
		},
		"bytes_read": 0,
		"user_id":    "",
		"duration":   0.004779453,
		"size":       615,
		"status":     200,
	}

	// Marshal to JSON
	logJSON, err := json.Marshal(logEntry)
	if err != nil {
		t.Fatalf("Failed to marshal log entry: %v", err)
	}

	// Write to the log writer
	n, err := writer.Write(logJSON)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	if n != len(logJSON) {
		t.Errorf("Expected to write %d bytes, wrote %d", len(logJSON), n)
	}

	// Wait for callback to be called (with timeout)
	select {
	case data := <-callbackChan:
		// Verify the extracted data
		if data.ServiceID != testServiceID {
			t.Errorf("Expected service_id %s, got %s", testServiceID, data.ServiceID)
		}
		if data.Method != "GET" {
			t.Errorf("Expected method GET, got %s", data.Method)
		}
		if data.Host != "test.netbird.io" {
			t.Errorf("Expected host test.netbird.io, got %s", data.Host)
		}
		if data.Path != "/test/path" {
			t.Errorf("Expected path /test/path, got %s", data.Path)
		}
		if data.ResponseCode != 200 {
			t.Errorf("Expected status 200, got %d", data.ResponseCode)
		}
		if data.SourceIP != "::1" {
			t.Errorf("Expected source_ip ::1, got %s", data.SourceIP)
		}
		// Duration should be ~4.78ms (0.004779453 * 1000)
		if data.DurationMs < 4 || data.DurationMs > 5 {
			t.Errorf("Expected duration ~4-5ms, got %dms", data.DurationMs)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Callback was not called within timeout")
	}

	// Verify callback was called
	callbackMu.Lock()
	defer callbackMu.Unlock()
	if !callbackCalled {
		t.Error("Callback was never called")
	}
}

func TestLogWriter_Write_NonAccessLog(t *testing.T) {
	// Create a channel to receive callback data
	callbackChan := make(chan *RequestData, 1)

	// Register a test callback
	testServiceID := "test-service-2"
	RegisterCallback(testServiceID, func(data *RequestData) {
		callbackChan <- data
	})
	defer UnregisterCallback(testServiceID)

	// Create a log writer
	writer := NewLogWriter(testServiceID)

	// Create a non-access log entry (e.g., a TLS log)
	logEntry := map[string]interface{}{
		"level":  "info",
		"ts":     1768352032.12347,
		"logger": "tls",
		"msg":    "storage cleaning happened too recently",
	}

	// Marshal to JSON
	logJSON, err := json.Marshal(logEntry)
	if err != nil {
		t.Fatalf("Failed to marshal log entry: %v", err)
	}

	// Write to the log writer
	n, err := writer.Write(logJSON)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	if n != len(logJSON) {
		t.Errorf("Expected to write %d bytes, wrote %d", len(logJSON), n)
	}

	// Callback should NOT be called for non-access logs
	select {
	case data := <-callbackChan:
		t.Errorf("Callback should not be called for non-access log, but got: %+v", data)
	case <-time.After(100 * time.Millisecond):
		// Expected - callback not called
	}
}

func TestLogWriter_Write_MalformedJSON(t *testing.T) {
	// Create a log writer
	writer := NewLogWriter("test-service-3")

	// Write malformed JSON
	malformedJSON := []byte("{this is not valid json")

	// Should not fail, just skip the entry
	n, err := writer.Write(malformedJSON)
	if err != nil {
		t.Fatalf("Write should not fail on malformed JSON: %v", err)
	}

	if n != len(malformedJSON) {
		t.Errorf("Expected to write %d bytes, wrote %d", len(malformedJSON), n)
	}
}

func TestCallbackRegistry(t *testing.T) {
	serviceID := "test-registry"
	var called bool

	// Test registering a callback
	callback := func(data *RequestData) {
		called = true
	}
	RegisterCallback(serviceID, callback)

	// Test retrieving the callback
	retrievedCallback := getCallback(serviceID)
	if retrievedCallback == nil {
		t.Fatal("Expected to retrieve callback, got nil")
	}

	// Call the retrieved callback to verify it works
	retrievedCallback(&RequestData{})
	if !called {
		t.Error("Callback was not called")
	}

	// Test unregistering
	UnregisterCallback(serviceID)
	retrievedCallback = getCallback(serviceID)
	if retrievedCallback != nil {
		t.Error("Expected nil after unregistering, got a callback")
	}
}

func TestCallbackWriter_Module(t *testing.T) {
	// Test that the module is properly configured
	cw := CallbackWriter{ServiceID: "test"}

	moduleInfo := cw.CaddyModule()
	if moduleInfo.ID != "caddy.logging.writers.callback" {
		t.Errorf("Expected module ID 'caddy.logging.writers.callback', got '%s'", moduleInfo.ID)
	}

	if moduleInfo.New == nil {
		t.Error("Expected New function to be set")
	}

	// Test creating a new instance via the New function
	newModule := moduleInfo.New()
	if newModule == nil {
		t.Error("Expected New() to return a module instance")
	}

	_, ok := newModule.(*CallbackWriter)
	if !ok {
		t.Error("Expected New() to return a *CallbackWriter")
	}
}

func TestCallbackWriter_WriterKey(t *testing.T) {
	cw := &CallbackWriter{ServiceID: "my-service"}

	expectedKey := "callback_my-service"
	if cw.WriterKey() != expectedKey {
		t.Errorf("Expected writer key '%s', got '%s'", expectedKey, cw.WriterKey())
	}
}

func TestCallbackWriter_String(t *testing.T) {
	cw := &CallbackWriter{ServiceID: "my-service"}

	str := cw.String()
	if str != "callback writer for service my-service" {
		t.Errorf("Unexpected string representation: %s", str)
	}
}

func TestLogWriter_Close(t *testing.T) {
	writer := NewLogWriter("test")

	// Close should not fail
	err := writer.Close()
	if err != nil {
		t.Errorf("Close should not fail: %v", err)
	}
}
