package autonoma

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"time"

	sdk "github.com/autonoma-ai/sdk/sdks/go/autonoma"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/shared/management/status"
)

// factories owns every factory closure. It holds the managers the closures
// create data through, so a factory body reads as the call the product makes.
type factories struct {
	deps    Deps
	cleaner cleaner
	// ctx is the request's context, minus its cancellation. Seeding has to run
	// to completion even if the caller hangs up: a half-created account whose
	// refs never reached the caller cannot be torn down. The values survive, so
	// every manager call a factory makes still logs and traces against the
	// request that asked for it.
	ctx context.Context
}

func writeJSON(w http.ResponseWriter, statusCode int, body map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		log.Errorf("autonoma: failed to write response: %v", err)
	}
}

// define builds a factory definition from a typed create/teardown pair. The
// SDK hands factories an `interface{}` it unmarshalled into InputStruct; this
// keeps that cast in one place so each factory body is plain typed Go.
func define[I any](
	f *factories,
	create func(ctx context.Context, in *I, fctx sdk.FactoryContext) (map[string]any, error),
	teardown func(ctx context.Context, record map[string]any) error,
) sdk.FactoryDefinition {
	def := sdk.FactoryDefinition{
		InputStruct: reflect.TypeOf(*new(I)),
		Create: func(input interface{}, fctx sdk.FactoryContext) (map[string]any, error) {
			in, ok := input.(*I)
			if !ok {
				return nil, fmt.Errorf("unexpected input type %T", input)
			}
			return create(f.ctx, in, fctx)
		},
	}
	if teardown != nil {
		def.Teardown = func(record interface{}, _ sdk.FactoryContext) error {
			rec, ok := record.(map[string]any)
			if !ok {
				return fmt.Errorf("unexpected record type %T", record)
			}
			return ignoreNotFound(teardown(f.ctx, rec))
		}
	}
	return def
}

// ignoreNotFound makes teardown idempotent. A row may already be gone because
// deleting the account cascaded into it, and the SDK tears down in reverse
// creation order regardless.
func ignoreNotFound(err error) error {
	if err == nil {
		return nil
	}
	var sErr *status.Error
	if errors.As(err, &sErr) && sErr.Type() == status.NotFound {
		return nil
	}
	if strings.Contains(strings.ToLower(err.Error()), "not found") {
		return nil
	}
	return err
}

// str reads a string out of a record the SDK stored during `up`.
func str(record map[string]any, key string) string {
	if v, ok := record[key].(string); ok {
		return v
	}
	return ""
}

// actorFor resolves the user id every manager call needs as its initiator: the
// owner of the account this run seeded. It only ever reads the Account records
// created earlier in the same run, so a recipe cannot name an account that
// already existed and have the endpoint act on it.
func (f *factories) actorFor(_ context.Context, fctx sdk.FactoryContext, accountID string) (string, error) {
	if accountID == "" {
		return "", fmt.Errorf("accountId is required")
	}
	for _, record := range fctx.Refs["Account"] {
		if str(record, "id") == accountID {
			if owner := str(record, "ownerUserId"); owner != "" {
				return owner, nil
			}
		}
	}

	// Anything not seeded by this run is out of scope on purpose. Falling back
	// to the stored owner would let a caller holding the shared secret act on -
	// and, through teardown, delete - an account it never created.
	return "", fmt.Errorf("account %s was not created in this run", accountID)
}

// lookupRef reads one field off a record another factory created earlier in the
// same run. It is how a factory turns a "{_ref: alias}" - which resolves to the
// referenced row's id - back into a different column of that row.
func lookupRef(fctx sdk.FactoryContext, model, id, field string) (string, error) {
	for _, record := range fctx.Refs[model] {
		if str(record, "id") == id {
			if value := str(record, field); value != "" {
				return value, nil
			}
			return "", fmt.Errorf("%s %s carries no %s", model, id, field)
		}
	}
	return "", fmt.Errorf("no %s with id %s was created in this run", model, id)
}

// minutesAgo turns a "this many minutes before seeding" offset into an instant.
// Recipes carry offsets, never timestamps: the same recipe is replayed for
// months, so anything the app compares against the current time has to be
// derived when the row is written, not when the recipe was authored.
func minutesAgo(minutes int) time.Time {
	return time.Now().UTC().Add(-time.Duration(minutes) * time.Minute)
}

// minutesFromNow is minutesAgo's forward-looking twin.
func minutesFromNow(minutes int) time.Time {
	return time.Now().UTC().Add(time.Duration(minutes) * time.Minute)
}

// orDefaultInt keeps zero-valued optional integers from turning into invalid
// durations or limits.
func orDefaultInt(value, fallback int) int {
	if value == 0 {
		return fallback
	}
	return value
}

func orDefaultStr(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

// timeLayout round-trips a timestamp through the refs the SDK signs into the
// teardown token, which carries JSON rather than Go values.
const timeLayout = time.RFC3339Nano

func nowUTC() time.Time { return time.Now().UTC() }

func parseTime(value string) (time.Time, error) {
	parsed, err := time.Parse(timeLayout, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("stored timestamp %q is unreadable: %w", value, err)
	}
	return parsed, nil
}

func strSlice(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}
