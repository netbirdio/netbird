package mcpapi

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// redisGrants keeps each grant as a hash and runs every change as a script, which Redis
// executes atomically. Keys are passed in KEYS, never built inside a script.
type redisGrants struct {
	client *redis.Client
}

// startScript: KEYS[1] is the code's use marker, KEYS[2] the new grant. ARGV[1] is the grant
// ID, ARGV[2] and ARGV[3] the marker's and the grant's TTL in milliseconds, then the fields.
var startScript = redis.NewScript(`
local previous = redis.call('GET', KEYS[1])
if previous then
  return {0, previous}
end
redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[2])
redis.call('HSET', KEYS[2], unpack(ARGV, 4))
redis.call('PEXPIRE', KEYS[2], ARGV[3])
return {1, ''}
`)

// rotateScript is rotateGrant. KEYS[1] is the grant. ARGV: presented, next, now and the
// grace window in milliseconds. It returns the outcome and the refresh ID to issue.
var rotateScript = redis.NewScript(`
local g = redis.call('HMGET', KEYS[1], 'r', 'p', 't')
local cur, prev, at = g[1], g[2], tonumber(g[3]) or 0
if not cur then
  return {0, ''}
end
local presented, now = ARGV[1], tonumber(ARGV[3])
local within = at ~= 0 and now - at <= tonumber(ARGV[4])
if presented == cur then
  if within then
    return {2, cur}
  end
  redis.call('HSET', KEYS[1], 'p', cur, 'r', ARGV[2], 't', ARGV[3])
  return {1, ARGV[2]}
end
if presented == prev and within then
  return {2, cur}
end
redis.call('DEL', KEYS[1])
return {3, ''}
`)

func newRedisGrants(ctx context.Context, redisURL string) (*redisGrants, error) {
	options, err := redis.ParseURL(redisURL)
	if err != nil {
		// The parse error quotes the URL, which may hold a password.
		return nil, errors.New("the redis URL does not parse")
	}
	client := redis.NewClient(options)
	pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := client.Ping(pingCtx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("reach redis: %w", err)
	}
	return &redisGrants{client: client}, nil
}

// Close closes the connection to Redis.
func (s *redisGrants) Close() error {
	return s.client.Close()
}

func (s *redisGrants) start(ctx context.Context, codeID string, codeTTL time.Duration, grantID string, record grantRecord, ttl time.Duration) (string, bool, error) {
	args := append([]any{grantID, codeTTL.Milliseconds(), ttl.Milliseconds()}, grantFields(record)...)
	res, err := startScript.Run(ctx, s.client, []string{usedCodeKeyPrefix + codeID, grantKeyPrefix + grantID}, args...).Slice()
	if err != nil {
		return "", false, fmt.Errorf("%w: start grant: %v", errStoreUnavailable, err)
	}
	created, previous, err := scriptReply(res)
	if err != nil {
		return "", false, err
	}
	return previous, created == 0, nil
}

func (s *redisGrants) claim(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	first, err := s.client.SetNX(ctx, key, "1", ttl).Result()
	if err != nil {
		return false, fmt.Errorf("%w: claim: %v", errStoreUnavailable, err)
	}
	return first, nil
}

func (s *redisGrants) load(ctx context.Context, grantID string) (grantRecord, bool, error) {
	fields, err := s.client.HGetAll(ctx, grantKeyPrefix+grantID).Result()
	if err != nil {
		return grantRecord{}, false, fmt.Errorf("%w: load grant: %v", errStoreUnavailable, err)
	}
	if fields["r"] == "" {
		return grantRecord{}, false, nil
	}
	rotatedAt, _ := strconv.ParseInt(fields["t"], 10, 64)
	started, _ := strconv.ParseInt(fields["s"], 10, 64)
	return grantRecord{
		UserID:    fields["u"],
		AccountID: fields["a"],
		ClientKey: fields["c"],
		Current:   fields["r"],
		Previous:  fields["p"],
		RotatedAt: rotatedAt,
		Started:   started,
	}, true, nil
}

func (s *redisGrants) rotate(ctx context.Context, grantID, presented, next string, now time.Time) (rotationOutcome, string, error) {
	args := []any{presented, next, now.UnixMilli(), refreshGrace.Milliseconds()}
	res, err := rotateScript.Run(ctx, s.client, []string{grantKeyPrefix + grantID}, args...).Slice()
	if err != nil {
		return grantGone, "", fmt.Errorf("%w: rotate grant: %v", errStoreUnavailable, err)
	}
	outcome, current, err := scriptReply(res)
	if err != nil {
		return grantGone, "", err
	}
	return rotationOutcome(outcome), current, nil
}

func (s *redisGrants) revoke(ctx context.Context, grantID string) error {
	if err := s.client.Del(ctx, grantKeyPrefix+grantID).Err(); err != nil {
		return fmt.Errorf("%w: revoke grant: %v", errStoreUnavailable, err)
	}
	return nil
}

// grantFields are a record's hash fields, in HSET's field, value order.
func grantFields(record grantRecord) []any {
	return []any{
		"u", record.UserID, "a", record.AccountID, "c", record.ClientKey,
		"r", record.Current, "p", record.Previous, "t", record.RotatedAt, "s", record.Started,
	}
}

// scriptReply reads the {number, string} pair the scripts return.
func scriptReply(res []any) (int64, string, error) {
	if len(res) != 2 {
		return 0, "", fmt.Errorf("%w: unexpected script reply", errStoreUnavailable)
	}
	n, ok := res[0].(int64)
	if !ok {
		return 0, "", fmt.Errorf("%w: unexpected script reply", errStoreUnavailable)
	}
	s, _ := res[1].(string)
	return n, s, nil
}
