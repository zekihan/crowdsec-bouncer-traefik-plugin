// Package cache implements utility routines for manipulating cache.
// It supports currently local file and redis cache.
package cache

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	ttl_map "github.com/leprosus/golang-ttl-map"
	simpleredis "github.com/maxlerebourg/simpleredis"
)

const (
	// BannedValue Banned string.
	BannedValue = "t"
	// NoBannedValue No banned string.
	NoBannedValue = "f"
	// CaptchaValue Need captcha string.
	CaptchaValue = "c"
	// CaptchaDoneValue Captcha done string.
	CaptchaDoneValue = "d"
	// CacheMiss error string when cache is miss.
	CacheMiss = "cache:miss"
	// CacheUnreachable error string when cache is unreachable.
	CacheUnreachable = "cache:unreachable"
)

//nolint:gochecknoglobals
var cache = ttl_map.New()

type localCache struct{}

func (localCache) get(key string) (string, error) {
	refreshMemory.Lock()
	defer refreshMemory.Unlock()
	value, isCached := cache.Get(key)
	valueString, isValid := value.(string)
	if isCached && isValid && len(valueString) > 0 {
		return valueString, nil
	}
	return "", errors.New(CacheMiss)
}

func (localCache) set(key, value string, duration int64) error {
	refreshMemory.Lock()
	defer refreshMemory.Unlock()
	cache.Set(key, value, duration)
	return nil
}

func (localCache) delete(key string) error {
	refreshMemory.Lock()
	defer refreshMemory.Unlock()
	cache.Del(key)
	return nil
}

type redisCache struct {
	prefix  string
	log     *slog.Logger
	writer  simpleredis.SimpleRedis
	readers []simpleredis.SimpleRedis
	counter atomic.Uint64
}

func (rc *redisCache) nextReader() *simpleredis.SimpleRedis {
	n := len(rc.readers)
	if n == 0 {
		return &rc.writer
	}
	idx := rc.counter.Add(1) % uint64(n)
	return &rc.readers[idx]
}

func (rc *redisCache) get(key string) (string, error) {
	value, err := rc.nextReader().Get(rc.prefix + key)
	if err != nil {
		switch err.Error() {
		case simpleredis.RedisMiss:
			return "", errors.New(CacheMiss)
		case simpleredis.RedisUnreachable:
			return "", errors.New(CacheUnreachable)
		default:
			return "", err
		}
	}
	valueString := string(value)
	if len(valueString) > 0 {
		return valueString, nil
	}
	return "", errors.New(CacheMiss)
}

func (rc *redisCache) set(key, value string, duration int64) error {
	return rc.writer.Set(rc.prefix+key, []byte(value), duration)
}

func (rc *redisCache) delete(key string) error {
	return rc.writer.Del(rc.prefix + key)
}

type cacheInterface interface {
	set(key, value string, duration int64) error
	get(key string) (string, error)
	delete(key string) error
}

// Client Cache client.
type Client struct {
	cache cacheInterface
	log   *slog.Logger
}

// New Initialize cache client.
func (c *Client) New(log *slog.Logger, isRedis bool, writeHost string, readHosts []string, pass, database string) {
	c.NewWithACL(log, isRedis, writeHost, readHosts, "", pass, database, "")
}

// NewWithACL configures an isolated Redis identity and key namespace.
func (c *Client) NewWithACL(log *slog.Logger, isRedis bool, writeHost string, readHosts []string, username, pass, database, prefix string) {
	c.Close()
	c.log = log
	if isRedis {
		rc := &redisCache{log: log, prefix: prefix}
		rc.writer.InitWithUsername(writeHost, username, pass, database)
		for _, h := range readHosts {
			var r simpleredis.SimpleRedis
			r.InitWithUsername(h, username, pass, database)
			rc.readers = append(rc.readers, r)
		}
		c.cache = rc
	} else {
		c.cache = &localCache{}
	}
	c.log.Debug(fmt.Sprintf("cache:New initialized isRedis:%v writeHost:%v readHosts:%v", isRedis, writeHost, readHosts))
}

// Delete delete decision in cache.
func (c *Client) Delete(key string) error {
	c.log.Debug(fmt.Sprintf("cache:Delete key:%v", key))
	return c.cache.delete(key)
}

// Get check in the cache if the IP has the banned / not banned value.
// Otherwise return with an error to add the IP in cache if we are on.
func (c *Client) Get(key string) (string, error) {
	c.log.Debug(fmt.Sprintf("cache:Get key:%v", key))
	return c.cache.get(key)
}

// Set update the cache with the IP as key and the value banned / not banned.
func (c *Client) Set(key string, value string, duration int64) error {
	c.log.Debug(fmt.Sprintf("cache:Set key:%v value:%v duration:%vs", key, value, duration))
	return c.cache.set(key, value, duration)
}

// ConfigurePool enables bounded connection reuse for each Redis endpoint.
func (c *Client) ConfigurePool(maxActive, maxIdle, maxWaiters, idleSeconds, lifetimeSeconds int) error {
	rc, ok := c.cache.(*redisCache)
	if !ok {
		return nil
	}
	options := simpleredis.PoolOptions{MaxActive: maxActive, MaxIdle: maxIdle, MaxWaiters: maxWaiters, IdleTimeout: time.Duration(idleSeconds) * time.Second, MaxLifetime: time.Duration(lifetimeSeconds) * time.Second}
	if err := rc.writer.ConfigurePool(options); err != nil {
		return err
	}
	for i := range rc.readers {
		if err := rc.readers[i].ConfigurePool(options); err != nil {
			c.Close()
			return err
		}
	}
	return nil
}

// Close retires all Redis endpoint pools owned by this middleware instance.
func (c *Client) Close() {
	rc, ok := c.cache.(*redisCache)
	if !ok {
		return
	}
	rc.writer.Close()
	for i := range rc.readers {
		rc.readers[i].Close()
	}
}

// GetContext cancels pooled request lookups without retaining a borrowed socket.
func (c *Client) GetContext(ctx context.Context, key string) (string, error) {
	rc, ok := c.cache.(*redisCache)
	if !ok {
		return c.Get(key)
	}
	c.log.Debug(fmt.Sprintf("cache:Get key:%v", key))
	value, err := rc.nextReader().GetContext(ctx, rc.prefix+key)
	if err != nil {
		switch err.Error() {
		case simpleredis.RedisMiss:
			return "", errors.New(CacheMiss)
		case simpleredis.RedisUnreachable:
			return "", errors.New(CacheUnreachable)
		}
		return "", err
	}
	if len(value) == 0 {
		return "", errors.New(CacheMiss)
	}
	return string(value), nil
}
