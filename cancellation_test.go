package crowdsec_bouncer_traefik_plugin //nolint:revive,stylecheck

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

func TestRetiredRefreshCancelsBlockedSnapshot(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		_, _ = io.WriteString(w, `{"new":[{"value":"192.0.2.99","type":"ban","duration":"1m"}],"deleted":[]}`)
	}))
	defer server.Close()
	endpoint, _ := url.Parse(server.URL)
	log := logger.New("ERROR", "")
	storage := &cache.Client{}
	storage.New(log, false, "", nil, "", "")
	_ = storage.Delete("updated")
	_ = storage.Delete("192.0.2.99")
	b := &Bouncer{crowdsecScheme: endpoint.Scheme, crowdsecHost: endpoint.Host, crowdsecHeader: "X-Api-Key", crowdsecStreamRoute: "/stream", updateInterval: 60, httpClient: server.Client(), cacheClient: storage, log: log}
	ctx, cancel := context.WithCancel(context.Background())
	done := startContextTicker(ctx, 60, true, func() { handleStreamTickerContext(ctx, b) })
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("request did not start")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		close(release)
		t.Fatal("refresh did not stop promptly")
	}
	close(release)
	if _, err := storage.Get("updated"); err == nil {
		t.Fatal("retired refresh published success")
	}
	if _, err := storage.Get("192.0.2.99"); err == nil {
		t.Fatal("retired refresh published a decision")
	}
}

func TestCanceledRefreshBeforeFetchAndCommit(t *testing.T) {
	log := logger.New("ERROR", "")
	storage := &cache.Client{}
	storage.New(log, false, "", nil, "", "")
	_ = storage.Delete("updated")
	_ = storage.Delete("192.0.2.98")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	b := &Bouncer{cacheClient: storage, log: log}
	if err := handleStreamCacheContext(ctx, b); err == nil {
		t.Fatal("canceled refresh started")
	}
	token, err := storage.BeginRefresh()
	if err != nil || token == "" {
		t.Fatal(token, err)
	}
	defer func() {
		if releaseErr := storage.EndRefresh(token); releaseErr != nil {
			t.Errorf("release refresh lease: %v", releaseErr)
		}
	}()
	entries := map[string]cache.SnapshotEntry{"192.0.2.98": {Value: cache.BannedValue, Until: time.Now().Add(time.Minute).UnixMilli()}}
	if err := storage.CommitRefreshContext(ctx, token, entries, nil, 60); err == nil {
		t.Fatal("canceled refresh committed")
	}
	if _, err := storage.Get("updated"); err == nil {
		t.Fatal("canceled refresh published success")
	}
	if _, err := storage.Get("192.0.2.98"); err == nil {
		t.Fatal("canceled refresh published decision")
	}
}
