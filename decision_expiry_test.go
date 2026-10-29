package crowdsec_bouncer_traefik_plugin //nolint:revive,stylecheck

import (
	"net/http"
	"testing"

	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

func TestLiveDecisionExpiry(t *testing.T) {
	const address = "192.0.2.181"
	for _, mode := range []string{configuration.LiveMode, configuration.NoneMode} {
		t.Run(mode, func(t *testing.T) {
			for _, test := range []struct {
				name string
				body string
				want string
			}{
				{"expired ban", `[{"type":"ban","duration":"-1s"}]`, cache.NoBannedValue},
				{"zero ban", `[{"type":"ban","duration":"0s"}]`, cache.NoBannedValue},
				{"expired ban before captcha", `[{"type":"ban","duration":"-1s"},{"type":"captcha","duration":"2m"}]`, cache.CaptchaValue},
				{"expired ban after captcha", `[{"type":"captcha","duration":"2m"},{"type":"ban","duration":"0s"}]`, cache.CaptchaValue},
				{"expired captcha after active captcha", `[{"type":"captcha","duration":"2m"},{"type":"captcha","duration":"-1s"}]`, cache.CaptchaValue},
				{"active ban after expired captcha", `[{"type":"captcha","duration":"-1s"},{"type":"ban","duration":"2m"}]`, cache.BannedValue},
				{"active ban before captcha", `[{"type":"ban","duration":"2m"},{"type":"captcha","duration":"2m"}]`, cache.BannedValue},
				{"null", `null`, cache.NoBannedValue},
				{"empty", `[]`, cache.NoBannedValue},
			} {
				t.Run(test.name, func(t *testing.T) {
					log := logger.New("ERROR", "")
					storage := &cache.Client{}
					storage.New(log, false, "", nil, "", "")
					if err := storage.Delete(address); err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = storage.Delete(address) })
					client := &http.Client{}
					client.Transport = snapshotTransport{body: test.body}
					bouncer := &Bouncer{
						crowdsecScheme: "http", crowdsecHost: "decisions.invalid", crowdsecMode: mode,
						defaultDecisionTimeout: 60, cacheClient: storage, log: log,
						httpClient: client,
					}
					got, err := handleNoStreamCache(bouncer, address)
					if got != test.want || (err != nil) != (test.want != cache.NoBannedValue) {
						t.Errorf("remediation = %q, %v; want %q", got, err, test.want)
					}
					cached, cacheErr := storage.Get(address)
					if mode == configuration.LiveMode {
						if cacheErr != nil || cached != test.want {
							t.Errorf("cached remediation = %q, %v; want %q", cached, cacheErr, test.want)
						}
					} else if cacheErr == nil {
						t.Errorf("none mode cached %q", cached)
					}
				})
			}
		})
	}
}
