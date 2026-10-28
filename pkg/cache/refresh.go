package cache

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"sync"
	"time"

	"github.com/maxlerebourg/simpleredis"
)

// RefreshLeaseDuration bounds an in-flight snapshot refresh.
const RefreshLeaseDuration = 30 * time.Second

// ErrRefreshBusy means another owner is refreshing, not that refresh failed.
var ErrRefreshBusy = errors.New("cache:refresh busy")

// SnapshotEntry preserves the decision's deadline across retries.
type SnapshotEntry struct {
	Value string `json:"value"`
	Until int64  `json:"until"`
}

// All coordination reads use the writer, never a potentially lagging replica.
const acquireRefresh = `
if redis.call('GET', KEYS[2]) then return 'updated' end
if redis.call('SET', KEYS[1], ARGV[1], 'NX', 'EX', ARGV[2]) then return 'acquired' end
return 'busy'
`
const releaseRefresh = `
if redis.call('GET', KEYS[1]) == ARGV[1] then redis.call('DEL', KEYS[1]) end
return 'OK'
`

// Preflight every command before mutating: Redis scripts do not roll back on errors.
//
//nolint:dupword // Lua block terminators are syntax, not repeated prose.
const commitRefresh = `
if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 'lost' end
local previous = cjson.decode(redis.call('GET', KEYS[3]) or '{}')
local current = cjson.decode(ARGV[2])
local removed = cjson.decode(ARGV[3])
local prefix = ARGV[5]
local function allowed(cmd, ...)
 if not redis.acl_check_cmd(cmd, ...) then error('NOPERM refresh command denied') end
end
for name, entry in pairs(current) do
 if type(name) ~= 'string' or type(entry.value) ~= 'string' or type(entry['until']) ~= 'number' or entry['until'] <= 0 then error('invalid snapshot') end
 allowed('SET', prefix .. name, entry.value, 'PXAT', tostring(entry['until']))
end
for name, _ in pairs(previous) do
 if not current[name] then allowed('DEL', prefix .. name) end
end
for _, name in ipairs(removed) do allowed('DEL', prefix .. name) end
allowed('SET', KEYS[3], ARGV[2])
allowed('SET', KEYS[2], 'f', 'EX', ARGV[4])
allowed('DEL', KEYS[1])
local tracked = {}
for name, entry in pairs(previous) do tracked[name] = entry end
for name, entry in pairs(current) do tracked[name] = entry end
redis.call('SET', KEYS[3], cjson.encode(tracked))
for name, _ in pairs(previous) do
 if not current[name] then redis.call('DEL', prefix .. name) end
end
for _, name in ipairs(removed) do
 if not current[name] then redis.call('DEL', prefix .. name) end
end
for name, entry in pairs(current) do
 redis.call('SET', prefix .. name, entry.value, 'PXAT', tostring(entry['until']))
end
redis.call('SET', KEYS[3], ARGV[2])
redis.call('SET', KEYS[2], 'f', 'EX', ARGV[4])
redis.call('DEL', KEYS[1])
return 'OK'
`

//nolint:gochecknoglobals
var refreshMemory = struct {
	sync.Mutex

	token    string
	until    time.Time
	previous map[string]SnapshotEntry
}{previous: make(map[string]SnapshotEntry)}

// HasFreshSnapshot checks only the committed success marker, using the writer.
func (c *Client) HasFreshSnapshot() (bool, error) {
	if rc, ok := c.cache.(*redisCache); ok {
		value, err := rc.writer.Get(rc.prefix + "updated")
		return validSnapshotMarker(string(value), err, simpleredis.RedisMiss)
	}
	value, err := c.cache.get("updated")
	return validSnapshotMarker(value, err, CacheMiss)
}

func validSnapshotMarker(value string, err error, miss string) (bool, error) {
	if err != nil {
		if err.Error() == miss {
			return false, nil
		}
		return false, err
	}
	if value != NoBannedValue {
		return false, errors.New("cache:invalid snapshot marker")
	}
	return true, nil
}

// BeginRefresh returns an owner token, or an empty token if already refreshed.
// A busy lease is an error, not evidence of a successfully populated cache.
func (c *Client) BeginRefresh() (string, error) {
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	token := hex.EncodeToString(random)
	if rc, ok := c.cache.(*redisCache); ok {
		result, err := rc.writer.Eval(acquireRefresh, []string{rc.prefix + "refresh:lease", rc.prefix + "updated"}, token, strconv.FormatInt(int64(RefreshLeaseDuration/time.Second), 10))
		if err != nil {
			return "", err
		}
		switch result {
		case "acquired":
			return token, nil
		case "updated":
			return "", nil
		case "busy":
			return "", ErrRefreshBusy
		default:
			return "", errors.New("cache:invalid refresh reply")
		}
	}
	refreshMemory.Lock()
	defer refreshMemory.Unlock()
	if _, ok := cache.Get("updated"); ok {
		return "", nil
	}
	if refreshMemory.token != "" && time.Now().Before(refreshMemory.until) {
		return "", ErrRefreshBusy
	}
	refreshMemory.token = token
	refreshMemory.until = time.Now().Add(RefreshLeaseDuration)
	return token, nil
}

// EndRefresh releases only the calling owner's lease.
func (c *Client) EndRefresh(token string) error {
	if rc, ok := c.cache.(*redisCache); ok {
		_, err := rc.writer.Eval(releaseRefresh, []string{rc.prefix + "refresh:lease"}, token)
		return err
	}
	refreshMemory.Lock()
	defer refreshMemory.Unlock()
	if refreshMemory.token == token {
		refreshMemory.token = ""
	}
	return nil
}

// CommitRefresh reconciles a complete startup=true snapshot and publishes success last.
func (c *Client) CommitRefresh(token string, entries map[string]SnapshotEntry, removed []string, markerTTL int64) error {
	for name := range entries {
		if name == "updated" || name == "refresh:lease" || name == "refresh:snapshot" {
			return errors.New("cache:reserved decision key")
		}
	}
	for _, name := range removed {
		if name == "updated" || name == "refresh:lease" || name == "refresh:snapshot" {
			return errors.New("cache:reserved decision key")
		}
	}
	if rc, ok := c.cache.(*redisCache); ok {
		return rc.commit(token, entries, removed, markerTTL)
	}

	refreshMemory.Lock()
	defer refreshMemory.Unlock()
	if refreshMemory.token != token || !time.Now().Before(refreshMemory.until) {
		return errors.New("cache:refresh lease lost")
	}
	for key := range refreshMemory.previous {
		if _, ok := entries[key]; !ok {
			cache.Del(key)
		}
	}
	for _, key := range removed {
		if _, ok := entries[key]; !ok {
			cache.Del(key)
		}
	}
	for key, entry := range entries {
		ttl := (entry.Until - time.Now().UnixMilli()) / 1000
		if ttl > 0 {
			cache.Set(key, entry.Value, ttl)
		} else {
			cache.Del(key)
		}
	}
	refreshMemory.previous = entries
	cache.Set("updated", NoBannedValue, markerTTL)
	refreshMemory.token = ""
	return nil
}

func (rc *redisCache) commit(token string, entries map[string]SnapshotEntry, removed []string, markerTTL int64) error {
	data, err := json.Marshal(entries)
	if err != nil {
		return err
	}
	if removed == nil {
		removed = []string{}
	}
	deleted, err := json.Marshal(removed)
	if err != nil {
		return err
	}
	result, err := rc.writer.Eval(commitRefresh, []string{rc.prefix + "refresh:lease", rc.prefix + "updated", rc.prefix + "refresh:snapshot"}, token, string(data), string(deleted), strconv.FormatInt(markerTTL, 10), rc.prefix)
	if err != nil {
		return err
	}
	if result != "OK" {
		return errors.New("cache:refresh lease lost")
	}
	return nil
}
