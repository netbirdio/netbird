package alignedhb

import (
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/netbirdio/netbird/shared/relay/messages"
)

// MetadataKey is the gRPC metadata key that carries the aligned heartbeat
// request when a Signal stream opens, and the answer in the header the Signal
// server sends back on that stream.
const MetadataKey = "x-netbird-aligned-heartbeat"

const (
	keyPeriod = "period"
	keyPhase  = "phase"
	keyDay    = "day"
	keySig    = "sig"

	// maxValueLen bounds a metadata value before it is parsed.
	maxValueLen = 512
	// MaxSignatureLen bounds the phase signature accepted on the wire, the
	// same bound as the relay extension.
	MaxSignatureLen = messages.MaxPhaseSignatureSize
	// maxPeriodSeconds keeps periods inside the relay extension field width.
	maxPeriodSeconds = math.MaxUint16
)

var (
	errValueTooLong = errors.New("value too long")
	errMissingField = errors.New("missing field")
)

// SignedPhase is a phase that Management signed for one peer and day.
type SignedPhase struct {
	Phase     time.Duration
	Day       int64
	Signature []byte
}

// StreamRequest is what a client sends when it opens a Signal stream.
type StreamRequest struct {
	Period time.Duration
	// Signed is the last signed phase from Management, nil until one is known.
	Signed *SignedPhase
}

// Answer is a server answer to an aligned heartbeat request: the period it
// confirmed and the phase it sends heartbeats on.
type Answer struct {
	Period time.Duration
	Phase  time.Duration
}

// Value encodes r as "period=<s>" plus ";phase=<ms>;day=<d>;sig=<base64>"
// when a signed phase is set.
func (r StreamRequest) Value() string {
	v := keyPeriod + "=" + strconv.FormatInt(int64(r.Period/time.Second), 10)
	if r.Signed == nil {
		return v
	}
	return fmt.Sprintf("%s;%s=%d;%s=%d;%s=%s", v,
		keyPhase, r.Signed.Phase.Milliseconds(),
		keyDay, r.Signed.Day,
		keySig, base64.StdEncoding.EncodeToString(r.Signed.Signature))
}

// ParseStreamRequest parses a value written by StreamRequest.Value. Unknown
// keys are ignored. The phase, day and signature come together or not at all.
func ParseStreamRequest(v string) (StreamRequest, error) {
	fields, err := parseFields(v)
	if err != nil {
		return StreamRequest{}, err
	}
	period, err := periodField(fields)
	if err != nil {
		return StreamRequest{}, err
	}
	if !hasSignedPhase(fields) {
		return StreamRequest{Period: period}, nil
	}
	signed, err := signedPhaseFields(fields, period)
	if err != nil {
		return StreamRequest{}, err
	}
	return StreamRequest{Period: period, Signed: signed}, nil
}

// Value encodes a as "period=<s>;phase=<ms>".
func (a Answer) Value() string {
	return fmt.Sprintf("%s=%d;%s=%d", keyPeriod, int64(a.Period/time.Second), keyPhase, a.Phase.Milliseconds())
}

// PendingAnswerValue encodes the answer to a request without a valid signed
// phase as "period=<s>". It tells the client that the server reads the stream,
// so the client may send the signed phase later.
func PendingAnswerValue(period time.Duration) string {
	return keyPeriod + "=" + strconv.FormatInt(int64(period/time.Second), 10)
}

// ParseStreamAnswer parses a value written by Answer.Value or
// PendingAnswerValue. aligned is false for a value without a phase: the stream
// stays stock until the server accepts a signed phase. Unknown keys are ignored.
func ParseStreamAnswer(v string) (a Answer, aligned bool, err error) {
	fields, err := parseFields(v)
	if err != nil {
		return Answer{}, false, err
	}
	period, err := periodField(fields)
	if err != nil {
		return Answer{}, false, err
	}
	raw, ok := fields[keyPhase]
	if !ok {
		return Answer{Period: period}, false, nil
	}
	phase, err := parsePhase(raw, period)
	if err != nil {
		return Answer{}, false, err
	}
	return Answer{Period: period, Phase: phase}, true, nil
}

// ValidPhase reports whether phase is a valid phase for period.
func ValidPhase(phase, period time.Duration) bool {
	return phase >= 0 && phase < period && phase%time.Millisecond == 0
}

func parseFields(v string) (map[string]string, error) {
	if len(v) > maxValueLen {
		return nil, fmt.Errorf("%d bytes: %w", len(v), errValueTooLong)
	}
	fields := make(map[string]string, 4)
	for _, part := range strings.Split(v, ";") {
		k, val, ok := strings.Cut(part, "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("malformed field %q", part)
		}
		if _, dup := fields[k]; dup {
			return nil, fmt.Errorf("duplicate field %q", k)
		}
		fields[k] = val
	}
	return fields, nil
}

func periodField(fields map[string]string) (time.Duration, error) {
	raw, ok := fields[keyPeriod]
	if !ok {
		return 0, fmt.Errorf("%s: %w", keyPeriod, errMissingField)
	}
	n, err := strconv.ParseUint(raw, 10, 16)
	if err != nil || n == 0 || n > maxPeriodSeconds {
		return 0, fmt.Errorf("invalid %s %q", keyPeriod, raw)
	}
	return time.Duration(n) * time.Second, nil
}

func parsePhase(raw string, period time.Duration) (time.Duration, error) {
	n, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid %s %q", keyPhase, raw)
	}
	phase := time.Duration(n) * time.Millisecond
	if !ValidPhase(phase, period) {
		return 0, fmt.Errorf("%s %d outside period %s", keyPhase, n, period)
	}
	return phase, nil
}

// hasSignedPhase reports whether fields carry any part of a signed phase.
func hasSignedPhase(fields map[string]string) bool {
	_, hasPhase := fields[keyPhase]
	_, hasDay := fields[keyDay]
	_, hasSig := fields[keySig]
	return hasPhase || hasDay || hasSig
}

// signedPhaseFields parses the signed phase in fields. The phase, day and
// signature must all be there.
func signedPhaseFields(fields map[string]string, period time.Duration) (*SignedPhase, error) {
	rawPhase, hasPhase := fields[keyPhase]
	rawDay, hasDay := fields[keyDay]
	rawSig, hasSig := fields[keySig]
	if !hasPhase || !hasDay || !hasSig {
		return nil, fmt.Errorf("%s, %s and %s must come together: %w", keyPhase, keyDay, keySig, errMissingField)
	}

	phase, err := parsePhase(rawPhase, period)
	if err != nil {
		return nil, err
	}
	day, err := strconv.ParseInt(rawDay, 10, 64)
	if err != nil || day < 0 {
		return nil, fmt.Errorf("invalid %s %q", keyDay, rawDay)
	}
	if base64.StdEncoding.DecodedLen(len(rawSig)) > MaxSignatureLen+2 {
		return nil, fmt.Errorf("%s: %w", keySig, errValueTooLong)
	}
	sig, err := base64.StdEncoding.DecodeString(rawSig)
	if err != nil {
		return nil, fmt.Errorf("invalid %s: %w", keySig, err)
	}
	if len(sig) == 0 || len(sig) > MaxSignatureLen {
		return nil, fmt.Errorf("invalid %s length %d", keySig, len(sig))
	}
	return &SignedPhase{Phase: phase, Day: day, Signature: sig}, nil
}
