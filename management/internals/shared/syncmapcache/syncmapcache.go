// Package syncmapcache records which network map each peer's Sync stream delivered,
// so a peer that reconnects to a restarted management server without logging in
// again can skip the map computation while it still holds the account's current map.
//
// An entry is a Redis hash per peer, keyed by its WireGuard public key. Its fields:
//   - login: a counter Login increments; a write that read an older value loses,
//     so a stream that predates a Login can never vouch for the new engine.
//   - sess: the Sync stream that owns the entry; only it may advance or release it.
//   - serial: the network serial of the last map the stream sent.
//   - gen: the build and map-affecting configuration that produced the map.
//   - kfp: the management key the stream's client decrypts with.
//   - at: when the stream last sent a full map, for the maximum age.
//   - rel: set when the stream ended because the server shut down, with nothing
//     left unsent and nothing sent in the moments before.
//
// A successful send does not prove the client received the message, and a stream
// the server still considers open may be dead behind a proxy. So only a released
// entry is reused: one whose stream the server itself ended. Every other entry is
// inert, and anything that may have left the peer behind removes its fields.
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
	// that skipped the computation gets a full map pushed.
	EnvResyncWindow = "NB_SYNC_MAP_CACHE_RESYNC_WINDOW"

	defaultMaxAge       = 48 * time.Hour
	defaultResyncWindow = 10 * time.Minute
	maxResyncWindow     = time.Hour
	entryTTL            = 7 * 24 * time.Hour
	opTimeout           = time.Second
	keyPrefix           = "nb:syncmap:"
	defaultReleaseGrace = 5 * time.Second
	// clockTolerance is how far in the future a delivery time may lie before the
	// writer's clock is distrusted.
	clockTolerance = 5 * time.Minute
)

// ErrClaimLost reports that a claim lost to a Login or to a change of the entry.
var ErrClaimLost = errors.New("sync map entry changed since it was read")

// PeerKey is a peer's WireGuard public key.
type PeerKey string

// Session identifies one Sync stream: its start in Unix nanoseconds, the same
// token the peer status uses to tell streams apart.
type Session int64

// KeyFingerprint identifies the management key a stream's client decrypts with.
type KeyFingerprint string

// Config controls the cache.
type Config struct {
	// Enabled allows reusing a released map on Sync and recording deliveries.
	Enabled bool
	// Generation identifies the build and the configuration that shape network
	// maps; entries written under another generation are not reused.
	Generation string
	// MaxAge bounds how long after its last delivered full map a peer may skip
	// the computation.
	MaxAge time.Duration
	// ResyncWindow bounds the random delay of the full push that follows a reuse.
	ResyncWindow time.Duration
	// ReleaseGrace is how long before shutdown a stream must have sent its last map
	// for its entry to be released: a hard stop drops frames still being flushed.
	ReleaseGrace time.Duration
}

// ConfigFromEnv reads the cache settings from the environment.
func ConfigFromEnv(generation string) Config {
	return Config{
		Enabled:      boolFromEnv(EnvEnabled),
		Generation:   generation,
		MaxAge:       durationFromEnv(EnvMaxAge, defaultMaxAge, 0),
		ResyncWindow: durationFromEnv(EnvResyncWindow, defaultResyncWindow, maxResyncWindow),
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
	client Client
	cfg    Config
	now    func() time.Time

	// shutdownAt is the BeginShutdown time in Unix nanoseconds, zero while running.
	shutdownAt atomic.Int64
	// streams counts the streams that may still release their entries.
	streams atomic.Int64
}

// New returns a cache over a Redis client. The resync push cannot be turned off:
// it bounds how long a change that does not move the network serial stays unseen.
func New(client Client, cfg Config) *Cache {
	if cfg.MaxAge <= 0 {
		cfg.MaxAge = defaultMaxAge
	}
	if cfg.ResyncWindow <= 0 || cfg.ResyncWindow > maxResyncWindow {
		cfg.ResyncWindow = defaultResyncWindow
	}
	if cfg.ReleaseGrace <= 0 {
		cfg.ReleaseGrace = defaultReleaseGrace
	}
	return &Cache{client: client, cfg: cfg, now: time.Now}
}

// Enabled reports whether Sync may reuse released maps and record deliveries.
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

// BeginShutdown marks the process as stopping. Streams that end from then on may
// release their entries, so their peers can skip the computation on the next
// instance.
func (c *Cache) BeginShutdown() {
	if c != nil {
		c.shutdownAt.CompareAndSwap(0, c.now().UnixNano())
	}
}

// ShuttingDown reports whether BeginShutdown was called.
func (c *Cache) ShuttingDown() bool {
	return c != nil && c.shutdownAt.Load() != 0
}

// StreamStarted counts a stream that may release its entry at shutdown.
func (c *Cache) StreamStarted() {
	c.streams.Add(1)
}

// StreamEnded uncounts a stream counted by StreamStarted.
func (c *Cache) StreamEnded() {
	c.streams.Add(-1)
}

// WaitStreams waits until every counted stream ended, or ctx ends. Shutdown calls
// it so releases are written before the process exits.
func (c *Cache) WaitStreams(ctx context.Context) {
	if c == nil {
		return
	}
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for c.streams.Load() > 0 {
		select {
		case <-ctx.Done():
			log.Warnf("stopped waiting for %d sync streams to release their network maps", c.streams.Load())
			return
		case <-ticker.C:
		}
	}
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
func (c *Cache) Lookup(ctx context.Context, peerKey PeerKey, key KeyFingerprint) (Lookup, error) {
	ctx, cancel := opContext(ctx)
	defer cancel()

	vals, err := c.client.HMGet(ctx, entryKey(peerKey), "login", "sess", "serial", "gen", "kfp", "at", "rel").Result()
	if err != nil {
		return Lookup{}, fmt.Errorf("read sync map entry: %w", err)
	}

	login, sess, serial, gen, kfp, at, rel := field(vals, 0), field(vals, 1), field(vals, 2), field(vals, 3), field(vals, 4), field(vals, 5), field(vals, 6)
	if login == "" {
		login = "0"
	}
	l := Lookup{login: login, session: sess}

	parsedSerial, err := strconv.ParseUint(serial, 10, 64)
	if err != nil || sess == "" || rel != "1" || gen != c.cfg.Generation || kfp != string(key) {
		return l, nil
	}
	deliveredAt, err := strconv.ParseInt(at, 10, 64)
	if err != nil || !c.fresh(time.Unix(deliveredAt, 0)) {
		return l, nil
	}

	l.serial = parsedSerial
	l.reusable = true
	return l, nil
}

func (c *Cache) fresh(deliveredAt time.Time) bool {
	now := c.now()
	if deliveredAt.After(now.Add(clockTolerance)) {
		return false
	}
	return now.Sub(deliveredAt) <= c.cfg.MaxAge
}

// ClaimDelivered records that the stream sent a full map of serial. It returns
// ErrClaimLost when a Login happened after seen was read.
func (c *Cache) ClaimDelivered(ctx context.Context, peerKey PeerKey, seen Lookup, session Session, serial uint64, key KeyFingerprint) error {
	return c.claim(ctx, peerKey, seen, session, serial, key, false)
}

// ClaimReused hands a released entry to a stream that reused the map instead of
// computing it. It returns ErrClaimLost when a Login or any change of the entry
// happened after seen was read.
func (c *Cache) ClaimReused(ctx context.Context, peerKey PeerKey, seen Lookup, session Session, key KeyFingerprint) error {
	if !seen.reusable {
		return ErrClaimLost
	}
	return c.claim(ctx, peerKey, seen, session, seen.serial, key, true)
}

func (c *Cache) claim(ctx context.Context, peerKey PeerKey, seen Lookup, session Session, serial uint64, key KeyFingerprint, reused bool) error {
	ctx, cancel := opContext(ctx)
	defer cancel()

	deliveredAt := strconv.FormatInt(c.now().Unix(), 10)
	reusedFlag := "0"
	if reused {
		reusedFlag = "1"
		deliveredAt = ""
	}

	applied, err := claimScript.Run(ctx, c.client, []string{entryKey(peerKey)},
		seen.login, formatSession(session), strconv.FormatUint(serial, 10), c.cfg.Generation, string(key),
		deliveredAt, int64(entryTTL.Seconds()), reusedFlag, seen.session).Int()
	if err != nil {
		return fmt.Errorf("claim sync map entry: %w", err)
	}
	if applied == 0 {
		return ErrClaimLost
	}
	return nil
}

// Advance records that the stream sent a full map of serial after its initial
// sync. It reports false when the stream no longer owns the entry.
func (c *Cache) Advance(ctx context.Context, peerKey PeerKey, session Session, serial uint64) (bool, error) {
	ctx, cancel := opContext(ctx)
	defer cancel()

	applied, err := advanceScript.Run(ctx, c.client, []string{entryKey(peerKey)},
		formatSession(session), strconv.FormatUint(serial, 10), strconv.FormatInt(c.now().Unix(), 10),
		int64(entryTTL.Seconds())).Int()
	if err != nil {
		return false, fmt.Errorf("advance sync map entry: %w", err)
	}
	return applied == 1, nil
}

// Release marks the stream's entry reusable after the server ended the stream on
// shutdown. It does nothing when the stream no longer owns the entry, or when it
// sent a map so shortly before the shutdown that the frames may not have left.
func (c *Cache) Release(ctx context.Context, peerKey PeerKey, session Session, lastSent time.Time) error {
	shutdownAt := c.shutdownAt.Load()
	if shutdownAt == 0 {
		return errors.New("release sync map entry: the server is not shutting down")
	}
	if lastSent.After(time.Unix(0, shutdownAt).Add(-c.cfg.ReleaseGrace)) {
		return nil
	}

	ctx, cancel := opContext(ctx)
	defer cancel()

	if _, err := releaseScript.Run(ctx, c.client, []string{entryKey(peerKey)}, formatSession(session)).Result(); err != nil {
		return fmt.Errorf("release sync map entry: %w", err)
	}
	return nil
}

// Invalidate forgets what any stream delivered to the peer.
func (c *Cache) Invalidate(ctx context.Context, peerKey PeerKey) error {
	ctx, cancel := opContext(ctx)
	defer cancel()

	if err := c.client.HDel(ctx, entryKey(peerKey), deliveryFields...).Err(); err != nil {
		return fmt.Errorf("invalidate sync map entry: %w", err)
	}
	return nil
}

// OnLogin invalidates the peer's entry and fences out writes from streams that
// read it before this Login, so a new engine always gets a full map. A peer
// without an entry is left alone: no stream can vouch for it without a Lookup,
// and Login must not create keys for keys it has not authenticated yet.
func (c *Cache) OnLogin(ctx context.Context, peerKey PeerKey) error {
	ctx, cancel := opContext(ctx)
	defer cancel()

	if _, err := loginScript.Run(ctx, c.client, []string{entryKey(peerKey)}, int64(entryTTL.Seconds())).Result(); err != nil {
		return fmt.Errorf("invalidate sync map entry on login: %w", err)
	}
	return nil
}

var deliveryFields = []string{"sess", "serial", "gen", "kfp", "at", "rel"}

// claimScript: KEYS[1] entry; ARGV login seen, session, serial, generation, key
// fingerprint, delivered-at ("" keeps it), ttl seconds, reused flag, session seen.
// A reuse claim also requires the released entry it read to be unchanged.
var claimScript = redis.NewScript(`
local login = redis.call('HGET', KEYS[1], 'login') or '0'
if login ~= ARGV[1] then
  return 0
end
local e = redis.call('HMGET', KEYS[1], 'sess', 'serial', 'at', 'rel')
if ARGV[8] == '1' and (e[1] ~= ARGV[9] or e[2] ~= ARGV[3] or not e[3] or e[4] ~= '1') then
  return 0
end
redis.call('HDEL', KEYS[1], 'rel')
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
if tonumber(ARGV[2]) > tonumber(e[2] or '0') then
  redis.call('HSET', KEYS[1], 'serial', ARGV[2])
end
redis.call('HDEL', KEYS[1], 'rel')
redis.call('HSET', KEYS[1], 'at', ARGV[3])
redis.call('EXPIRE', KEYS[1], ARGV[4])
return 1
`)

// releaseScript: KEYS[1] entry; ARGV session.
var releaseScript = redis.NewScript(`
if redis.call('HGET', KEYS[1], 'sess') ~= ARGV[1] then
  return 0
end
redis.call('HSET', KEYS[1], 'rel', '1')
return 1
`)

// loginScript: KEYS[1] entry; ARGV ttl seconds.
var loginScript = redis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 0 then
  return 0
end
redis.call('HINCRBY', KEYS[1], 'login', 1)
redis.call('HDEL', KEYS[1], 'sess', 'serial', 'gen', 'kfp', 'at', 'rel')
redis.call('EXPIRE', KEYS[1], ARGV[1])
return 1
`)

// opContext bounds a Redis operation by its own timeout only: invalidations often run
// as a stream ends, when the stream's context is already cancelled.
func opContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), opTimeout)
}

func entryKey(peerKey PeerKey) string {
	return keyPrefix + string(peerKey)
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

// durationFromEnv parses a positive duration, capped at upper when upper is set.
func durationFromEnv(name string, def, upper time.Duration) time.Duration {
	val := os.Getenv(name)
	if val == "" {
		return def
	}
	d, err := time.ParseDuration(val)
	if err != nil || d <= 0 || (upper > 0 && d > upper) {
		log.Warnf("invalid %s %q, using %s", name, val, def)
		return def
	}
	return d
}
