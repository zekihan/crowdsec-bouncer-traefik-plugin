package cache

import (
	"os"
	"testing"
	"time"

	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
	"github.com/maxlerebourg/simpleredis"
)

// Run against the disposable ACL fixture, never a production Redis endpoint.
func TestRedisRefreshRegression(t *testing.T) {
	host := os.Getenv("REDIS_REFRESH_FIXTURE")
	if host == "" {
		t.Skip("requires disposable Redis fixture")
	}
	log := logger.New("ERROR", "")
	a, b := &Client{}, &Client{}
	prefix := "crowdsec:regression:"
	a.NewWithACL(log, true, host, nil, "crowdsec", "fixture password%value", "11", prefix)
	b.NewWithACL(log, true, host, []string{"127.0.0.1:1"}, "crowdsec", "fixture password%value", "11", prefix)
	var admin simpleredis.SimpleRedis
	admin.InitWithUsername(host, "admin", "fixture-admin", "11")
	//nolint:intrange // Keep test syntax compatible with Yaegi v0.16.1.
	for i := 0; i < 100; i++ {
		requireCacheSuccess(t, admin.Del(prefix+"updated"))
		token, err := a.BeginRefresh()
		if err != nil || token == "" {
			t.Fatal(token, err)
		}
		if _, err = b.BeginRefresh(); err == nil {
			t.Fatal("overlapping refresh acquired lease")
		}
		requireCacheSuccess(t, b.EndRefresh("wrong"))
		if _, err = b.BeginRefresh(); err == nil {
			t.Fatal("wrong owner released lease")
		}
		entries := map[string]SnapshotEntry{"192.0.2.41": {Value: BannedValue, Until: time.Now().Add(time.Minute).UnixMilli()}}
		requireCacheSuccess(t, a.CommitRefresh(token, entries, []string{}, 1))
		if token, err = b.BeginRefresh(); err != nil || token != "" {
			t.Fatal("coordination used stale reader", token, err)
		}
		requireCacheSuccess(t, admin.Del(prefix+"updated"))
		next, err := b.BeginRefresh()
		if err != nil {
			t.Fatal(err)
		}
		if err = a.CommitRefresh("wrong", entries, []string{}, 1); err == nil {
			t.Fatal("lost owner committed")
		}
		requireCacheSuccess(t, b.CommitRefresh(next, map[string]SnapshotEntry{}, []string{}, 1))
		if _, err = a.Get("192.0.2.41"); err == nil {
			t.Fatal("absent decision not reconciled")
		}
		requireCacheSuccess(t, admin.Del(prefix+"updated"))
		expired, err := a.BeginRefresh()
		if err != nil {
			t.Fatal(err)
		}
		requireCacheSuccess(t, admin.Set(prefix+"refresh:lease", []byte("successor"), 30))
		if err = a.CommitRefresh(expired, entries, []string{}, 1); err == nil {
			t.Fatal("expired owner committed")
		}
		requireCacheSuccess(t, a.EndRefresh(expired))
		if value, getErr := admin.Get(prefix + "refresh:lease"); getErr != nil || string(value) != "successor" {
			t.Fatal("expired owner released successor", getErr)
		}
		requireCacheSuccess(t, admin.Del(prefix+"refresh:lease"))
	}
}
