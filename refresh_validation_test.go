package crowdsec_bouncer_traefik_plugin //nolint:revive,stylecheck

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

func TestSnapshotShapePreservesCache(t *testing.T) {
	var responseMu sync.RWMutex
	response := `{"new":[],"deleted":[]}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		responseMu.RLock()
		defer responseMu.RUnlock()
		_, _ = io.WriteString(w, response)
	}))
	defer server.Close()
	endpoint, _ := url.Parse(server.URL)
	log := logger.New("ERROR", "")
	storage := &cache.Client{}
	storage.New(log, false, "", nil, "", "")
	b := &Bouncer{crowdsecScheme: endpoint.Scheme, crowdsecHost: endpoint.Host, crowdsecHeader: "X-Api-Key", crowdsecStreamRoute: "/stream", updateInterval: 60, httpClient: server.Client(), cacheClient: storage, log: log}
	for _, invalid := range []string{`null`, `{}`, `{"message":"wrong endpoint"}`, `[]`, `{"new":[]}`, `{"deleted":[]}`, `{"new":{},"deleted":[]}`} {
		if err := storage.Delete("updated"); err != nil {
			t.Fatal(err)
		}
		token, err := storage.BeginRefresh()
		if err != nil {
			t.Fatal(err)
		}
		if err = storage.CommitRefresh(token, map[string]cache.SnapshotEntry{"192.0.2.44": {Value: cache.BannedValue, Until: time.Now().Add(time.Minute).UnixMilli()}}, nil, 60); err != nil {
			t.Fatal(err)
		}
		if err = storage.Delete("updated"); err != nil {
			t.Fatal(err)
		}
		responseMu.Lock()
		response = invalid
		responseMu.Unlock()
		if err = handleStreamCache(b); err == nil {
			t.Fatalf("accepted invalid snapshot %s", invalid)
		}
		if value, getErr := storage.Get("192.0.2.44"); getErr != nil || value != cache.BannedValue {
			t.Fatalf("invalid snapshot erased ban: %s", invalid)
		}
		if _, getErr := storage.Get("updated"); getErr == nil {
			t.Fatal("invalid snapshot published success")
		}
	}
	for _, valid := range []string{`{"new":[],"deleted":[]}`, `{"new":null,"deleted":null}`} {
		responseMu.Lock()
		response = valid
		responseMu.Unlock()
		if err := storage.Delete("updated"); err != nil {
			t.Fatal(err)
		}
		if err := handleStreamCache(b); err != nil {
			t.Fatal(err)
		}
		if _, err := storage.Get("192.0.2.44"); err == nil {
			t.Fatal("empty snapshot retained ban")
		}
	}
	_ = storage.Delete("updated")
}

func TestRefreshContentionPreservesHealth(t *testing.T) {
	storage := &cache.Client{}
	log := logger.New("ERROR", "")
	storage.New(log, false, "", nil, "", "")
	if err := storage.Delete("updated"); err != nil {
		t.Fatal(err)
	}
	token, err := storage.BeginRefresh()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = storage.EndRefresh(token) }()
	for _, state := range []struct{ healthy, startup int32 }{{1, 0}, {0, 0}, {0, 1}, {1, 1}} {
		b := &Bouncer{cacheClient: storage, log: log, streamHealthy: state.healthy, streamStartup: state.startup, updateFailures: 2, updateMaxFailure: 0}
		handleStreamTicker(b)
		if atomic.LoadInt32(&b.streamHealthy) != state.healthy || atomic.LoadInt32(&b.streamStartup) != state.startup || atomic.LoadInt64(&b.updateFailures) != 2 {
			t.Fatalf("contention changed health/startup/failure state: %+v", state)
		}
	}
}

func TestInvalidLeaseReplyIsFailure(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		if _, readErr := readFixtureCommand(bufio.NewReader(conn)); readErr != nil {
			return
		}
		_, _ = io.WriteString(conn, "$2\r\nOK\r\n")
	}()
	defer func() { _ = listener.Close(); <-done }()
	log := logger.New("ERROR", "")
	storage := &cache.Client{}
	storage.New(log, true, listener.Addr().String(), nil, "", "")
	b := &Bouncer{cacheClient: storage, log: log, streamHealthy: 1, updateMaxFailure: 0}
	handleStreamTicker(b)
	if atomic.LoadInt32(&b.streamHealthy) != 0 || atomic.LoadInt64(&b.updateFailures) != 1 {
		t.Fatal("invalid reply was mistaken for contention")
	}
}

func TestFailedOwnerCannotKeepFollowerHealthy(t *testing.T) {
	log := logger.New("ERROR", "")
	storage := &cache.Client{}
	storage.New(log, false, "", nil, "", "")
	defer func() { _ = storage.Delete("updated") }()
	follower := &Bouncer{cacheClient: storage, log: log, streamHealthy: 1, updateInterval: 1, updateMaxFailure: 0, streamLastSuccess: time.Now().UnixNano()}
	failOpen := &Bouncer{cacheClient: storage, log: log, streamHealthy: 1, updateInterval: 1, updateMaxFailure: -1, streamLastSuccess: time.Now().Add(-time.Hour).UnixNano()}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		handleStreamTicker(follower)
		handleStreamTicker(failOpen)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	endpoint, _ := url.Parse(server.URL)
	owner := &Bouncer{crowdsecScheme: endpoint.Scheme, crowdsecHost: endpoint.Host, crowdsecHeader: "X-Api-Key", crowdsecStreamRoute: "/stream", updateInterval: 1, httpClient: server.Client(), cacheClient: storage, log: log}
	for cycle := 0; cycle < 3; cycle++ { //nolint:intrange // Keep loop syntax compatible with Yaegi v0.16.1.
		if err := storage.Delete("updated"); err != nil {
			t.Fatal(err)
		}
		if err := handleStreamCache(owner); err == nil {
			t.Fatal("expected failed owner")
		}
		if cycle == 0 {
			if atomic.LoadInt32(&follower.streamHealthy) != 1 {
				t.Fatal("ordinary contention blocked follower")
			}
			atomic.StoreInt64(&follower.streamLastSuccess, time.Now().Add(-cache.RefreshLeaseDuration-2*time.Second).UnixNano())
		} else if atomic.LoadInt32(&follower.streamHealthy) != 0 {
			t.Fatal("failed owner kept stale follower healthy")
		}
		if atomic.LoadInt32(&failOpen.streamHealthy) != 1 {
			t.Fatal("explicit fail-open changed")
		}
		if atomic.LoadInt64(&follower.updateFailures) != 0 {
			t.Fatal("contention counted as owner failure")
		}
	}
	token, err := storage.BeginRefresh()
	if err != nil {
		t.Fatal(err)
	}
	if err = storage.CommitRefresh(token, map[string]cache.SnapshotEntry{}, nil, 60); err != nil {
		t.Fatal(err)
	}
	handleStreamTicker(follower)
	if atomic.LoadInt32(&follower.streamHealthy) != 1 || time.Since(time.Unix(0, atomic.LoadInt64(&follower.streamLastSuccess))) > time.Second {
		t.Fatal("shared success did not recover follower")
	}
}

func TestContentionHealthBudget(t *testing.T) {
	for _, failures := range []int64{0, 2, 5} {
		b := &Bouncer{streamHealthy: 1, updateInterval: 10, updateMaxFailure: failures}
		limit := cache.RefreshLeaseDuration + time.Duration(failures+1)*10*time.Second
		atomic.StoreInt64(&b.streamLastSuccess, time.Now().Add(-limit+time.Second).UnixNano())
		b.expireStreamHealth()
		if atomic.LoadInt32(&b.streamHealthy) != 1 {
			t.Fatal("health expired before its budget")
		}
		atomic.StoreInt64(&b.streamLastSuccess, time.Now().Add(-limit-time.Second).UnixNano())
		b.expireStreamHealth()
		if atomic.LoadInt32(&b.streamHealthy) != 0 {
			t.Fatal("health exceeded its budget")
		}
	}
}
