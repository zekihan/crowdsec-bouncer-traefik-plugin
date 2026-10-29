package crowdsec_bouncer_traefik_plugin //nolint:revive,stylecheck

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

type snapshotTransport struct {
	body string
}

func (transport snapshotTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(transport.body)), Header: make(http.Header), Request: req}, nil
}

func TestStreamBanPrecedesCaptcha(t *testing.T) {
	const address = "192.0.2.180"
	for _, test := range []struct {
		name      string
		decisions string
		want      string
	}{
		{"ban then captcha", `{"type":"ban","duration":"2m"},{"type":"captcha","duration":"1m"}`, cache.BannedValue},
		{"captcha then ban", `{"type":"captcha","duration":"1m"},{"type":"ban","duration":"2m"}`, cache.BannedValue},
		{"short ban then long captcha", `{"type":"ban","duration":"1m"},{"type":"captcha","duration":"2m"}`, cache.BannedValue},
		{"expired ban then captcha", `{"type":"ban","duration":"-1s"},{"type":"captcha","duration":"2m"}`, cache.CaptchaValue},
		{"captcha then expired ban", `{"type":"captcha","duration":"2m"},{"type":"ban","duration":"0s"}`, cache.CaptchaValue},
	} {
		t.Run(test.name, func(t *testing.T) {
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
			decisions := strings.ReplaceAll(test.decisions, `{"type":`, `{"value":"`+address+`","type":`)
			client := &http.Client{}
			client.Transport = snapshotTransport{body: `{"new":[` + decisions + `],"deleted":[]}`}
			bouncer := &Bouncer{
				crowdsecScheme: "http", crowdsecHost: "snapshot.invalid", crowdsecStreamRoute: "/stream",
				updateInterval: 60, cacheClient: storage, log: log,
				httpClient: client,
			}
			if err := handleStreamCache(bouncer); err != nil {
				t.Fatal(err)
			}
			if got, err := storage.Get(address); err != nil || got != test.want {
				t.Fatalf("snapshot remediation = %q, %v; want %q", got, err, test.want)
			}
		})
	}
}
