package crowdsec_bouncer_traefik_plugin //nolint:revive,stylecheck

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

func readFixtureCommand(r *bufio.Reader) ([]string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	count, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "*")))
	if err != nil || count < 1 || count > 16 {
		return nil, errors.New("invalid command count")
	}
	args := make([]string, count)
	for i := range args {
		line, err = r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		size, parseErr := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "$")))
		if parseErr != nil || size < 0 || size > 4096 {
			return nil, errors.New("invalid command size")
		}
		data := make([]byte, size+2)
		if _, err = io.ReadFull(r, data); err != nil {
			return nil, err
		}
		args[i] = string(data[:size])
	}
	return args, nil
}

func TestStreamCacheWriteFailures(t *testing.T) {
	for _, failure := range []string{"DEL", "SET", "marker"} {
		t.Run(failure, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = listener.Close() }()
			var mutex sync.Mutex
			markerWrites := 0
			go serveRedisFault(listener, failure, &mutex, &markerWrites)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, `{"deleted":[{"value":"192.0.2.1"}],"new":[{"type":"ban","value":"192.0.2.2","duration":"1h"}]}`)
			}))
			defer server.Close()
			endpoint, err := url.Parse(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			log := logger.New("ERROR", "")
			storage := &cache.Client{}
			storage.NewWithACL(log, true, listener.Addr().String(), nil, "", "", "", "crowdsec:")
			bouncer := &Bouncer{crowdsecScheme: endpoint.Scheme, crowdsecHost: endpoint.Host,
				crowdsecHeader: "X-Api-Key", crowdsecStreamRoute: "/v1/decisions/stream", updateInterval: 60,
				httpClient: server.Client(), cacheClient: storage, log: log}
			if err = handleStreamCache(bouncer); err == nil {
				t.Fatal("failed write reported successful refresh")
			}
			mutex.Lock()
			defer mutex.Unlock()
			if failure != "marker" && markerWrites != 0 {
				t.Fatal("published marker after failed decision write")
			}
			if failure == "marker" && markerWrites != 1 {
				t.Fatal("marker failure was not exercised")
			}
		})
	}
}

func serveRedisFault(listener net.Listener, failure string, mutex *sync.Mutex, markerWrites *int) {
	for {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		args, readErr := readFixtureCommand(bufio.NewReader(conn))
		if readErr != nil {
			_ = conn.Close()
			continue
		}
		response := "$2\r\nOK\r\n"
		if args[0] == "EVAL" && strings.Contains(args[1], "return 'acquired'") {
			response = "$8\r\nacquired\r\n"
		}
		if args[0] == "EVAL" && strings.Contains(args[1], "acl_check_cmd") {
			if failure == "marker" {
				mutex.Lock()
				(*markerWrites)++
				mutex.Unlock()
			}
			response = "-NOPERM fixture denial\r\n"
		}

		_, _ = io.WriteString(conn, response)
		_ = conn.Close()
	}
}
