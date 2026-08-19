package netutil

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidatePort(t *testing.T) {
	tests := []struct {
		name    string
		port    int32
		want    uint16
		wantErr bool
	}{
		{"valid min", 1, 1, false},
		{"valid mid", 8080, 8080, false},
		{"valid max", 65535, 65535, false},
		{"zero", 0, 0, true},
		{"negative", -1, 0, true},
		{"too large", 65536, 0, true},
		{"way too large", 100000, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ValidatePort(tt.port)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Zero(t, got)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestIsExpectedError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"net.ErrClosed", net.ErrClosed, true},
		{"context.Canceled", context.Canceled, true},
		{"io.EOF", io.EOF, true},
		{"ECONNRESET", syscall.ECONNRESET, true},
		{"EPIPE", syscall.EPIPE, true},
		{"ECONNABORTED", syscall.ECONNABORTED, true},
		{"wrapped expected", fmt.Errorf("wrap: %w", net.ErrClosed), true},
		{"unexpected EOF", io.ErrUnexpectedEOF, false},
		{"generic error", errors.New("something"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, IsExpectedError(tt.err))
		})
	}
}

type timeoutErr struct{ timeout bool }

func (e *timeoutErr) Error() string   { return "timeout" }
func (e *timeoutErr) Timeout() bool   { return e.timeout }
func (e *timeoutErr) Temporary() bool { return false }

func TestIsTimeout(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"net timeout", &timeoutErr{timeout: true}, true},
		{"net non-timeout", &timeoutErr{timeout: false}, false},
		{"wrapped timeout", fmt.Errorf("wrap: %w", &timeoutErr{timeout: true}), true},
		{"generic error", errors.New("not a timeout"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, IsTimeout(tt.err))
		})
	}
}
