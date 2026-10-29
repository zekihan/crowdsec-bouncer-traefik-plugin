package crowdsec_bouncer_traefik_plugin //nolint:revive,stylecheck

import (
	"net/http"
	"strings"
	"testing"

	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

func TestStreamRetainsLongestSameTypeDecision(t *testing.T) {
	const address = "192.0.2.182"
	for _, decisionType := range []string{"ban", "captcha"} {
		for _, durations := range []string{`"2m","500ms"`, `"500ms","2m"`} {
			t.Run(decisionType+"/"+durations, func(t *testing.T) {
				log := logger.New("ERROR", "")
				storage := &cache.Client{}
				storage.New(log, false, "", nil, "", "")
				if err := storage.Delete("updated"); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					_ = storage.Delete("updated")
					_ = storage.Delete(address)
				})
				var decisions []string
				for _, duration := range strings.Split(durations, ",") {
					decisions = append(decisions, `{"value":"`+address+`","type":"`+decisionType+`","duration":`+duration+`}`)
				}
				client := &http.Client{}
				client.Transport = snapshotTransport{body: `{"new":[` + strings.Join(decisions, ",") + `],"deleted":[]}`}
				bouncer := &Bouncer{
					crowdsecScheme: "http", crowdsecHost: "snapshot.invalid", crowdsecStreamRoute: "/stream",
					updateInterval: 60, cacheClient: storage, log: log, httpClient: client,
				}
				if err := handleStreamCache(bouncer); err != nil {
					t.Fatal(err)
				}
				want := cache.BannedValue
				if decisionType == "captcha" {
					want = cache.CaptchaValue
				}
				// A subsecond duplicate must not erase the still-active two-minute decision.
				if got, err := storage.Get(address); err != nil || got != want {
					t.Fatalf("snapshot remediation = %q, %v; want %q for the longer decision", got, err, want)
				}
			})
		}
	}
}
