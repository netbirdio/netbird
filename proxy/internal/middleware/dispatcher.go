package middleware

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"time"

	log "github.com/sirupsen/logrus"
)

// Dispatcher reliability kinds reported via
// proxy.middleware.errors_total{kind=...}.
const (
	ErrorKindPanic       = "panic"
	ErrorKindTimeout     = "timeout"
	ErrorKindInvokeError = "invoke_error"
)

// Dispatcher drives a single middleware invocation with panic
// recovery, deadline, and output filtering. Safe for concurrent use.
type Dispatcher struct {
	metrics *Metrics
	logger  *log.Logger
}

// NewDispatcher returns a dispatcher that emits on the provided
// metrics bundle and logger. A nil metrics bundle falls back to a noop
// instrument set; a nil logger falls back to the standard logger.
func NewDispatcher(metrics *Metrics, logger *log.Logger) *Dispatcher {
	if metrics == nil {
		metrics, _ = NewMetrics(nil)
	}
	if logger == nil {
		logger = log.StandardLogger()
	}
	return &Dispatcher{metrics: metrics, logger: logger}
}

// Invoke runs a single middleware under the reliability wrappers:
// deadline, panic recovery (type + truncated stack only), fail-mode,
// metric emission, and output filtering. The returned output is always
// safe to apply.
func (d *Dispatcher) Invoke(ctx context.Context, spec Spec, mw Middleware, in *Input) (*Output, error) {
	if mw == nil {
		return nil, fmt.Errorf("middleware %s: instance unavailable", spec.ID)
	}

	timeout := clampTimeout(spec.Timeout)
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	d.metrics.IncInvocation(ctx, spec.ID)
	start := time.Now()

	type result struct {
		out *Output
		err error
	}
	ch := make(chan result, 1)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				stack := make([]byte, 4<<10)
				n := runtime.Stack(stack, false)
				requestID := ""
				if in != nil {
					requestID = in.RequestID
				}
				d.logger.Warnf("middleware %s panic: request_id=%s type=%s stack=%s",
					spec.ID, requestID, reflect.TypeOf(r).String(), stack[:n])
				ch <- result{err: panicError{msg: fmt.Sprintf("middleware %s panic: %s", spec.ID, reflect.TypeOf(r).String())}}
			}
		}()
		out, err := mw.Invoke(callCtx, in)
		ch <- result{out: out, err: err}
	}()

	var (
		out    *Output
		invErr error
		kind   string
	)

	select {
	case <-callCtx.Done():
		invErr = callCtx.Err()
		kind = ErrorKindTimeout
	case res := <-ch:
		out = res.out
		invErr = res.err
		if invErr != nil {
			kind = d.classifyError(invErr)
		}
	}

	d.metrics.ObserveDuration(ctx, spec.ID, time.Since(start).Milliseconds())

	if invErr != nil {
		d.metrics.IncError(ctx, spec.ID, kind)
		return d.failMode(spec, kind), invErr
	}

	return d.filterOutput(spec, out), nil
}

func (d *Dispatcher) classifyError(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return ErrorKindTimeout
	}
	var pe panicError
	if errors.As(err, &pe) {
		return ErrorKindPanic
	}
	return ErrorKindInvokeError
}

// panicError marks an error as coming from the recover branch so the
// classifier can tag it without string inspection.
type panicError struct{ msg string }

func (p panicError) Error() string { return p.msg }

// failMode converts an error into a synthesised output per the
// middleware's fail-mode. An mw.<id>.error_kind metadata entry is
// attached so operators can alert on error rate even when the
// decision is fail-open. Slot constraints still apply: response and
// terminal slots clamp deny back to passthrough in filterOutput.
func (d *Dispatcher) failMode(spec Spec, kind string) *Output {
	meta := []KV{{Key: fmt.Sprintf(KeyFrameworkErrorKindFmt, spec.ID), Value: kind}}
	if spec.FailMode == FailClosed && spec.Slot == SlotOnRequest {
		return &Output{
			Decision:   DecisionDeny,
			DenyStatus: 500,
			DenyReason: &DenyReason{Code: "middleware.error"},
			Metadata:   meta,
		}
	}
	return &Output{Decision: DecisionAllow, Metadata: meta}
}

// filterOutput applies the output-filter pipeline (slot-aware decision
// clamp, mutations gate) so downstream consumers never see
// middleware-supplied values that violate the contract. Metadata is
// passed through; the Accumulator is the single owner of allowlist +
// caps + redaction (called by Chain).
func (d *Dispatcher) filterOutput(spec Spec, out *Output) *Output {
	if out == nil {
		return &Output{Decision: DecisionAllow}
	}
	if spec.Slot != SlotOnRequest && out.Decision == DecisionDeny {
		out.Decision = DecisionPassthrough
		out.DenyStatus = 0
		out.DenyReason = nil
	}
	if out.Decision == DecisionDeny {
		if out.DenyStatus == 0 {
			out.DenyStatus = 403
		} else {
			out.DenyStatus = clampDenyStatus(out.DenyStatus)
		}
	}
	if !spec.CanMutate || !spec.MutationsSupported {
		out.Mutations = nil
	}
	if spec.Slot == SlotTerminal {
		out.Mutations = nil
	}
	return out
}

func clampTimeout(d time.Duration) time.Duration {
	if d <= 0 {
		return DefaultTimeout
	}
	if d < MinTimeout {
		return MinTimeout
	}
	if d > MaxTimeout {
		return MaxTimeout
	}
	return d
}
