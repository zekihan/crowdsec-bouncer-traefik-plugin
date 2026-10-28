package crowdsec_bouncer_traefik_plugin //nolint:revive,stylecheck

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

func TestBlockedFollowersAdoptCommittedSnapshotWithoutAnotherTick(t *testing.T) {
	storage := &cache.Client{}
	storage.New(logger.New("ERROR", ""), false, "", nil, "", "")
	for _, key := range []string{"updated", "192.0.2.200", "2001:db8::200"} {
		if err := storage.Delete(key); err != nil {
			t.Fatal(err)
		}
		defer func(key string) { _ = storage.Delete(key) }(key)
	}
	owner, err := storage.BeginRefresh()
	if err != nil || owner == "" {
		t.Fatal("could not acquire synthetic owner lease", err)
	}
	defer func() { _ = storage.EndRefresh(owner) }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	followers := make([]*Bouncer, 0, 2)
	for _, name := range []string{"first", "second"} {
		cfg := getTestConfig()
		cfg.CrowdsecMode = configuration.StreamMode
		cfg.StreamStartupBlock = true
		cfg.UpdateIntervalSeconds = 300
		cfg.UpdateMaxFailure = -1
		handler, newErr := New(ctx, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }), cfg, name)
		if newErr != nil {
			t.Fatal(newErr)
		}
		follower, ok := handler.(*Bouncer)
		if !ok {
			t.Fatal("unexpected follower handler type")
		}
		followers = append(followers, follower)
		if code := followerStatus(follower, "192.0.2.201"); code != http.StatusForbidden {
			t.Fatalf("uncommitted owner allowed request: %d", code)
		}
	}
	entries := map[string]cache.SnapshotEntry{
		"192.0.2.200":   {Value: cache.BannedValue, Until: time.Now().Add(time.Minute).UnixMilli()},
		"2001:db8::200": {Value: cache.BannedValue, Until: time.Now().Add(time.Minute).UnixMilli()},
	}
	if err := storage.CommitRefresh(owner, entries, nil, 299); err != nil {
		t.Fatal(err)
	}
	for _, follower := range followers {
		assertFollowerSnapshot(t, storage, follower)
	}
}

func assertFollowerSnapshot(t *testing.T, storage *cache.Client, follower *Bouncer) {
	t.Helper()

	for _, addr := range []string{"192.0.2.201", "2001:db8::201"} {
		if code := followerStatus(follower, addr); code != http.StatusOK {
			t.Errorf("committed snapshot left follower blocked until its next 300s tick: %s status=%d", addr, code)
		}
	}
	for _, addr := range []string{"192.0.2.200", "2001:db8::200"} {
		if code := followerStatus(follower, addr); code != http.StatusForbidden {
			t.Errorf("shared snapshot ban bypassed: %s status=%d", addr, code)
		}
	}
	if err := storage.Set("updated", "invalid", 60); err != nil {
		t.Fatal(err)
	}
	atomic.StoreInt32(&follower.streamHealthy, 0)
	if code := followerStatus(follower, "192.0.2.201"); code != http.StatusForbidden {
		t.Errorf("invalid marker allowed request: %d", code)
	}
	if err := storage.Delete("updated"); err != nil {
		t.Fatal(err)
	}
	if code := followerStatus(follower, "192.0.2.201"); code != http.StatusForbidden {
		t.Errorf("missing marker allowed request: %d", code)
	}
	if err := storage.Set("updated", cache.NoBannedValue, 299); err != nil {
		t.Fatal(err)
	}
}

func followerStatus(follower *Bouncer, addr string) int {
	request := httptest.NewRequest(http.MethodGet, "http://fixture/crowdsec-ready", nil)
	request.RemoteAddr = net.JoinHostPort(addr, "12345")
	response := httptest.NewRecorder()
	follower.ServeHTTP(response, request)
	return response.Code
}
