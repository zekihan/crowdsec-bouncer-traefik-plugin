package cache

import (
	"testing"
	"time"

	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

func TestRefreshOwnershipAndSnapshot(t *testing.T) {
	first, second := &Client{}, &Client{}
	first.New(logger.New("ERROR", ""), false, "", nil, "", "")
	second.New(logger.New("ERROR", ""), false, "", nil, "", "")
	requireCacheSuccess(t, first.Delete("updated"))
	token, err := first.BeginRefresh()
	if err != nil || token == "" {
		t.Fatal(token, err)
	}
	if _, err = second.BeginRefresh(); err == nil {
		t.Fatal("overlapping refresh acquired lease")
	}
	if err = second.EndRefresh("wrong-owner"); err != nil {
		t.Fatal(err)
	}
	if _, err = second.BeginRefresh(); err == nil {
		t.Fatal("wrong owner released lease")
	}
	until := time.Now().Add(time.Minute).UnixMilli()
	if err = first.CommitRefresh(token, map[string]SnapshotEntry{"192.0.2.41": {Value: BannedValue, Until: until}}, nil, 1); err != nil {
		t.Fatal(err)
	}
	requireCacheSuccess(t, first.Delete("updated"))
	next, err := second.BeginRefresh()
	if err != nil {
		t.Fatal(err)
	}
	if err = first.CommitRefresh(token, map[string]SnapshotEntry{}, nil, 1); err == nil {
		t.Fatal("retired owner committed")
	}
	if err = second.CommitRefresh(next, map[string]SnapshotEntry{"192.0.2.42": {Value: BannedValue, Until: until}}, nil, 1); err != nil {
		t.Fatal(err)
	}
	if _, err = first.Get("192.0.2.41"); err == nil {
		t.Fatal("deleted decision survived full reconciliation")
	}
	if v, err := first.Get("192.0.2.42"); err != nil || v != BannedValue {
		t.Fatal(v, err)
	}
	requireCacheSuccess(t, first.Delete("updated"))
}
