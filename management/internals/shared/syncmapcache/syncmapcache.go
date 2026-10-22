// Package syncmapcache records which network map each peer's Sync stream delivered,
// so a peer that reconnects without logging in again, as every peer does after a
// management restart, can skip the map computation while it still holds the
// account's current map.
//
// An entry is a Redis hash per peer, keyed by its WireGuard public key. Its fields:
//   - login: a counter Login increments; a write that read an older value loses,
//     so a stream that predates a Login can never vouch for the new engine.
//   - sess: the Sync stream that owns the entry; only it may advance the serial.
//   - serial: the network serial of the last map delivered on that stream.
//   - gen: the build and map-affecting configuration that produced the map.
//   - kfp: the management key the stream's client decrypts with.
//   - at: when a full map was last delivered, for the maximum age.
//
// Anything that may have left the peer behind removes every field but login, and
// the next Sync computes the map again.
package syncmapcache

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
	log "github.com/sirupsen/logrus"
)

const (
	// EnvEnabled turns on reusing a delivered network map on Sync. Login always
	// invalidates entries when Redis is configured, so enabling this later is safe.
	EnvEnabled = "NB_SYNC_MAP_CACHE_ENABLED"
	// EnvMaxAge bounds how long after its last delivered full map a peer may skip
	// the computation.
	EnvMaxAge = "NB_SYNC_MAP_CACHE_MAX_AGE"
	// EnvResyncWindow is the upper bound of the random delay after which a peer
	// that skipped the computation gets a full map pushed. Zero disables the push.
	EnvResyncWindow = "NB_SYNC_MAP_CACHE_RESYNC_WINDOW"

	defaultMaxAge       = 48 * time.Hour
	defaultResyncWindow = 10 * time.Minute
	entryTTL            = 7 * 24 * time.Hour
	opTimeout           = time.Second
	keyPrefix           = "nb:syncmap:"
)

// Session identifies one Sync stream: its start in Unix nanoseconds, the same
// token the peer status uses to tell streams apart.
type Session int64

// KeyFingerprint identifies the management key a stream's client decrypts with.
type KeyFingerprint string

// Config controls the cache.
type Config struct {
	// Enabled allows reusing a delivered map on Sync and recording deliveries.
	Enabled bool
	// Generation identifies the build and the configuration that shape network
	// maps; entries written under another generation are not reused.
	Generation string
	// MaxAge bounds how long after its last delivered full map a peer may skip
	// the computation.
	MaxAge time.Duration
	// ResyncWindow bounds the random delay of the full push that follows a reuse.
	// Zero disables it.
	ResyncWindow time.Duration
}

// ConfigFromEnv reads the cache settings from the environment.
func ConfigFromEnv(generation string) Config {
	return Config{
		Enabled:      boolFromEnv(EnvEnabled),
		Generation:   generation,
		MaxAge:       durationFromEnv(EnvMaxAge, defaultMaxAge, false),
		ResyncWindow: durationFromEnv(EnvResyncWindow, defaultResyncWindow, true),
	}
}

// Client is the part of the Redis client the cache uses.
type Client interface {
	redis.Scripter
	HMGet(ctx context.Context, key string, fields ...string) *redis.SliceCmd
	HDel(ctx context.Context, key string, fields ...string) *redis.IntCmd
}

// Cache reads and writes the per-peer entries.
type Cache struct {
	client       Client
	cfg          Config
	shuttingDown atomic.Bool
	now          func() time.Time
}

// New returns a cache over a Redis client.
func New(client Client, cfg Config) *Cache {
	if cfg.MaxAge <= 0 {
		cfg.MaxAge = defaultMaxAge
	}
	if cfg.ResyncWindow < 0 {
		cfg.ResyncWindow = 0
	}
	return &Cache{client: client, cfg: cfg, now: time.Now}
}

// Enabled reports whether Sync may reuse delivered maps and record deliveries.
func (c *Cache) Enabled() bool {
	return c != nil && c.cfg.Enabled
}

// ResyncWindow returns the upper bound of the delayed full push after a reuse.
func (c *Cache) ResyncWindow() time.Duration {
	if c == nil {
		return 0
	}
	return c.cfg.ResyncWindow
}

// BeginShutdown marks the process as stopping. Streams that end from then on keep
// their entries, so their peers can skip the computation on the next instance.
func (c *Cache) BeginShutdown() {
	if c != nil {
		c.shuttingDown.Store(true)
	}
}

// ShuttingDown reports whether BeginShutdown was called.
func (c *Cache) ShuttingDown() bool {
	return c != nil && c.shuttingDown.Load()
}

// Lookup is the state of a peer's entry when its Sync started.
type Lookup struct {
	login    string
	session  string
	serial   uint64
	reusable bool
}

// Serial returns the serial the peer holds, and false when the entry cannot be
// reused.
func (l Lookup) Serial() (uint64, bool) {
	return l.serial, l.reusable
}

// Lookup reads the peer's entry. The result decides whether the map may be reused
// and fences the write that follows the Sync against a concurrent Login.
func (c *Cache) Lookup(ctx context.Context, peerKey string, key KeyFingerprint) (Lookup, error) {
	ctx, cancel := opContext(ctx)
	defer cancel()

	vals, err := c.client.HMGet(ctx, entryKey(peerKey), "login", "sess", "serial", "gen", "kfp", "at").Result()
	if err != nil {
		return Lookup{}, fmt.Errorf("read sync map entry: %w", err)
	}

	login, sess, serial, gen, kfp, at := field(vals, 0), field(vals, 1), field(vals, 2), field(vals, 3), field(vals, 4), field(vals, 5)
	if login == "" {
		login = "0"
	}
	l := Lookup{login: login, session: sess}

	parsedSerial, err := strconv.ParseUint(serial, 10, 64)
	if err != nil || sess == "" || gen != c.cfg.Generation || kfp != string(key) {
		return l, nil
	}
	deliveredAt, err := strconv.ParseInt(at, 10, 64)
	if err != nil || c.now().Sub(time.Unix(deliveredAt, 0)) > c.cfg.MaxAge {
		return l, nil
	}

	l.serial = parsedSerial
	l.reusable = true
	return l, nil
}

// ClaimDelivered records that the stream delivered a full map of serial. It loses
// to a Login that happened after seen was read.
func (c *Cache) ClaimDelivered(ctx context.Context, peerKey string, seen Lookup, session Session, serial uint64, key KeyFingerprint) error {
	return c.claim(ctx, peerKey, seen, session, serial, key, false)
}

// ClaimReused hands the entry to a stream that reused the map instead of computing
// it. It loses to a Login after seen was read, and to any change of the entry.
func (c *Cache) ClaimReused(ctx context.Context, peerKey string, seen Lookup, session Session, key KeyFingerprint) error {
	if !seen.reusable {
		return errors.New("claim reused: entry was not reusable")
	}
	return c.claim(ctx, peerKey, seen, session, seen.serial, key, true)
}

func (c *Cache) claim(ctx context.Context, peerKey string, seen Lookup, session Session, serial uint64, key KeyFingerprint, reused bool) error {
	ctx, cancel := opContext(ctx)
	defer cancel()

	deliveredAt := strconv.FormatInt(c.now().Unix(), 10)
	reusedFlag := "0"
	if reused {
		reusedFlag = "1"
		deliveredAt = ""
	}

	_, err := claimScript.Run(ctx, c.client, []string{entryKey(peerKey)},
		seen.login, formatSession(session), strconv.FormatUint(serial, 10), c.cfg.Generation, string(key),
		deliveredAt, int64(entryTTL.Seconds()), reusedFlag, seen.session).Result()
	if err != nil {
		return fmt.Errorf("claim sync map entry: %w", err)
	}
	return nil
}

// Advance records that the stream delivered a full map of serial after its initial
// sync. Only the stream that owns the entry advances it, and never backwards.
func (c *Cache) Advance(ctx context.Context, peerKey string, session Session, serial uint64) error {
	ctx, cancel := opContext(ctx)
	defer cancel()

	_, err := advanceScript.Run(ctx, c.client, []string{entryKey(peerKey)},
		formatSession(session), strconv.FormatUint(serial, 10), strconv.FormatInt(c.now().Unix(), 10),
		int64(entryTTL.Seconds())).Result()
	if err != nil {
		return fmt.Errorf("advance sync map entry: %w", err)
	}
	return nil
}

// Invalidate forgets what any stream delivered to the peer.
func (c *Cache) Invalidate(ctx context.Context, peerKey string) error {
	ctx, cancel := opContext(ctx)
	defer cancel()

	if err := c.client.HDel(ctx, entryKey(peerKey), deliveryFields...).Err(); err != nil {
		return fmt.Errorf("invalidate sync map entry: %w", err)
	}
	return nil
}

// InvalidateAsync invalidates the peer's entry without blocking the caller, for
// paths that hold locks.
func (c *Cache) InvalidateAsync(ctx context.Context, peerKey string) {
	go func(ctx context.Context, peerKey string) {
		if err := c.Invalidate(ctx, peerKey); err != nil {
			log.WithContext(ctx).Warnf("failed to invalidate sync map entry of peer %s: %v", peerKey, err)
		}
	}(ctx, peerKey)
}

// InvalidateSession forgets what the stream delivered, unless another stream owns
// the entry by now.
func (c *Cache) InvalidateSession(ctx context.Context, peerKey string, session Session) error {
	ctx, cancel := opContext(ctx)
	defer cancel()

	_, err := invalidateSessionScript.Run(ctx, c.client, []string{entryKey(peerKey)}, formatSession(session)).Result()
	if err != nil {
		return fmt.Errorf("invalidate sync map entry of session: %w", err)
	}
	return nil
}

// OnLogin invalidates the peer's entry and fences out writes from streams that
// started before this Login, so a new engine always gets a full map.
func (c *Cache) OnLogin(ctx context.Context, peerKey string) error {
	ctx, cancel := opContext(ctx)
	defer cancel()

	_, err := loginScript.Run(ctx, c.client, []string{entryKey(peerKey)}, int64(entryTTL.Seconds())).Result()
	if err != nil {
		return fmt.Errorf("invalidate sync map entry on login: %w", err)
	}
	return nil
}

var deliveryFields = []string{"sess", "serial", "gen", "kfp", "at"}

// claimScript: KEYS[1] entry; ARGV login seen, session, serial, generation, key
// fingerprint, delivered-at ("" keeps it), ttl seconds, reused flag, session seen.
var claimScript = redis.NewScript(`
local login = redis.call('HGET', KEYS[1], 'login') or '0'
if login ~= ARGV[1] then
  return 0
end
local e = redis.call('HMGET', KEYS[1], 'sess', 'serial', 'at')
if ARGV[8] == '1' and (e[1] ~= ARGV[9] or e[2] ~= ARGV[3] or not e[3]) then
  return 0
end
redis.call('HSET', KEYS[1], 'sess', ARGV[2], 'serial', ARGV[3], 'gen', ARGV[4], 'kfp', ARGV[5])
if ARGV[6] ~= '' then
  redis.call('HSET', KEYS[1], 'at', ARGV[6])
end
redis.call('EXPIRE', KEYS[1], ARGV[7])
return 1
`)

// advanceScript: KEYS[1] entry; ARGV session, serial, delivered-at, ttl seconds.
var advanceScript = redis.NewScript(`
local e = redis.call('HMGET', KEYS[1], 'sess', 'serial')
if e[1] ~= ARGV[1] then
  return 0
end
if tonumber(ARGV[2]) < tonumber(e[2] or '0') then
  return 0
end
redis.call('HSET', KEYS[1], 'serial', ARGV[2], 'at', ARGV[3])
redis.call('EXPIRE', KEYS[1], ARGV[4])
return 1
`)

// invalidateSessionScript: KEYS[1] entry; ARGV session.
var invalidateSessionScript = redis.NewScript(`
if redis.call('HGET', KEYS[1], 'sess') ~= ARGV[1] then
  return 0
end
redis.call('HDEL', KEYS[1], 'sess', 'serial', 'gen', 'kfp', 'at')
return 1
`)

// loginScript: KEYS[1] entry; ARGV ttl seconds.
var loginScript = redis.NewScript(`
redis.call('HINCRBY', KEYS[1], 'login', 1)
redis.call('HDEL', KEYS[1], 'sess', 'serial', 'gen', 'kfp', 'at')
redis.call('EXPIRE', KEYS[1], ARGV[1])
return 1
`)

// opContext bounds a Redis operation by its own timeout only: invalidations often run
// as a stream ends, when the stream's context is already cancelled.
func opContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), opTimeout)
}

func entryKey(peerKey string) string {
	return keyPrefix + peerKey
}

func formatSession(s Session) string {
	return strconv.FormatInt(int64(s), 10)
}

func field(vals []any, i int) string {
	if i >= len(vals) {
		return ""
	}
	s, _ := vals[i].(string)
	return s
}

func boolFromEnv(name string) bool {
	val := os.Getenv(name)
	if val == "" {
		return false
	}
	enabled, err := strconv.ParseBool(val)
	if err != nil {
		log.Warnf("failed to parse %s: %v", name, err)
		return false
	}
	return enabled
}

func durationFromEnv(name string, def time.Duration, allowZero bool) time.Duration {
	val := os.Getenv(name)
	if val == "" {
		return def
	}
	d, err := time.ParseDuration(val)
	if err != nil || d < 0 || (d == 0 && !allowZero) {
		log.Warnf("invalid %s %q, using %s", name, val, def)
		return def
	}
	return d
}
