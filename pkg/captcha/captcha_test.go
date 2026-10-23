package captcha

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

func TestFailedCacheWriteDoesNotSolveCaptcha(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	defer provider.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = conn.Write([]byte("-NOPERM fixture denial\r\n"))
	}()
	log := logger.New("ERROR", "")
	storage := &cache.Client{}
	storage.NewWithACL(log, true, listener.Addr().String(), nil, "", "", "", "crowdsec:")
	client := &Client{cacheClient: storage, httpClient: provider.Client(), log: log,
		infoProvider:       &infoProvider{response: "token", validate: provider.URL},
		gracePeriodSeconds: 60, remediationCustomHeader: "X-Remediation"}
	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("token=valid"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	client.ServeHTTP(response, request, "192.0.2.1")
	if response.Code != http.StatusServiceUnavailable || response.Header().Get("Location") != "" || response.Header().Get("X-Remediation") != "" {
		t.Fatalf("failed cache write reported success: %d %v", response.Code, response.Header())
	}
}
