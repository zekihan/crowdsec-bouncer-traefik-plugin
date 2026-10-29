// Package crowdsec_bouncer_traefik_plugin implements a middleware that communicates with crowdsec.
// It can cache results in memory or using redis, or even ask crowdsec for every requests.
package crowdsec_bouncer_traefik_plugin //nolint:revive,stylecheck

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"text/template"
	"time"

	cache "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	captcha "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/captcha"
	configuration "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	ip "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/ip"
	logger "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

const (
	crowdsecAppsecIPHeader          = "X-Crowdsec-Appsec-Ip"
	crowdsecAppsecURIHeader         = "X-Crowdsec-Appsec-Uri"
	crowdsecAppsecHostHeader        = "X-Crowdsec-Appsec-Host"
	crowdsecAppsecVerbHeader        = "X-Crowdsec-Appsec-Verb"
	crowdsecAppsecHeader            = "X-Crowdsec-Appsec-Api-Key"
	crowdsecAppsecUserAgent         = "X-Crowdsec-Appsec-User-Agent"
	crowdsecAppsecHTTPVersionHeader = "X-Crowdsec-Appsec-Http-Version"
	crowdsecLapiHeader              = "X-Api-Key"
	crowdsecLapiRoute               = "v1/decisions"
	crowdsecLapiStreamRoute         = "v1/decisions/stream"
	crowdsecLapiMetricsRoute        = "v1/usage-metrics"
	crowdsecCapiHost                = "api.crowdsec.net"
	crowdsecCapiHeader              = "Authorization"
	crowdsecCapiLoginRoute          = "v2/watchers/login"
	crowdsecCapiStreamRoute         = "v2/decisions/stream"
	cacheTimeoutKey                 = "updated"
	appsecAllowAction               = "allow"
	appsecChallengeAction           = "challenge"
	appsecCaptchaAction             = "captcha"
	appsecChallengePathPrefix       = "/crowdsec-internal/challenge/"
	appsecResponseBodyLimit         = 1 << 20 // 1 MiB
	statusClientClosedRequest       = 499
)

var errAppsecGetBody = errors.New("appsecQuery:GetBody")

// Metrics remain shared across routes. Stream state and refresh lifetimes belong
// to each middleware instance so replacement configurations use their own cache.
//
//nolint:gochecknoglobals
var (
	metricsTicker   *time.Ticker
	lastMetricsPush time.Time
	blockedRequests int64
)

// CreateConfig creates the default plugin configuration.
func CreateConfig() *configuration.Config {
	return configuration.New()
}

// Bouncer a Bouncer struct.
type Bouncer struct {
	streamHealthy     int32
	streamStartup     int32
	updateFailures    int64
	streamLastSuccess int64
	next              http.Handler
	name              string
	template          *template.Template

	enabled                   bool
	appsecEnabled             bool
	appsecScheme              string
	appsecHost                string
	appsecPath                string
	appsecKey                 string
	appsecFailureBlock        bool
	appsecUnreachableBlock    bool
	appsecUnreadableBodyBlock bool
	appsecBodyLimit           int64
	crowdsecScheme            string
	crowdsecHost              string
	crowdsecPath              string
	crowdsecKey               string
	crowdsecMode              string
	crowdsecMachineID         string
	crowdsecPassword          string
	crowdsecScenarios         []string
	updateInterval            int64
	updateMaxFailure          int64
	defaultDecisionTimeout    int64
	remediationStatusCode     int
	remediationCustomHeader   string
	forwardedCustomHeader     string
	crowdsecStreamRoute       string
	crowdsecHeader            string
	redisUnreachableBlock     bool
	banTemplate               *template.Template
	banTemplateContentType    string
	traceCustomHeader         string
	clientPoolStrategy        *ip.PoolStrategy
	serverPoolStrategy        *ip.PoolStrategy
	httpClient                *http.Client
	httpAppsecClient          *http.Client
	cacheClient               *cache.Client
	captchaClient             *captcha.Client
	log                       *slog.Logger
}

// AppSecResponse is the structured remediation Appsec returns for a request.
type AppSecResponse struct {
	Action          string              `json:"action"`
	HTTPStatus      int                 `json:"http_status"`                 //nolint:tagliatelle
	UserBodyContent string              `json:"user_body_content,omitempty"` //nolint:tagliatelle
	UserCookies     []string            `json:"user_cookies,omitempty"`      //nolint:tagliatelle
	UserHeaders     map[string][]string `json:"user_headers,omitempty"`      //nolint:tagliatelle
}

// New creates the crowdsec bouncer plugin.
//
//nolint:gocyclo,gocognit,funlen,maintidx
func New(ctx context.Context, next http.Handler, config *configuration.Config, name string) (http.Handler, error) {
	config.LogLevel = strings.ToUpper(config.LogLevel)
	log := logger.NewWithFormat(config.LogLevel, config.LogFilePath, config.LogFormat)

	if config.BanFilePath == "" && config.BanHTMLFilePath != "" {
		config.BanFilePath = config.BanHTMLFilePath
	}
	if config.CaptchaHTMLFilePath != "" {
		config.CaptchaFilePath = config.CaptchaHTMLFilePath
	}

	err := configuration.ValidateParams(config, log)
	if err != nil {
		log.Error("New:validateParams " + err.Error())
		return nil, err
	}

	serverChecker, _ := ip.NewChecker(log, config.ForwardedHeadersTrustedIPs)
	clientChecker, _ := ip.NewChecker(log, config.ClientTrustedIPs)

	var tlsAppsecConfig *tls.Config
	if config.CrowdsecAppsecEnabled {
		tlsAppsecConfig, err = configuration.GetTLSConfigCrowdsec(config, log, true)
		if config.CrowdsecAppsecScheme == "" {
			config.CrowdsecAppsecScheme = config.CrowdsecLapiScheme
		}
		if err != nil {
			log.Error("New:getTLSConfigCrowdsec fail to get tlsAppsecConfig " + err.Error())
			return nil, err
		}
		apiAppsecKey, errAppsecKey := configuration.GetVariable(config, "CrowdsecAppsecKey")
		if errAppsecKey != nil && len(tlsAppsecConfig.Certificates) == 0 {
			log.Info("New:crowdsecLapiKey fail to get CrowdsecAppsecKey and no client certificate setup " + errAppsecKey.Error())
		}
		config.CrowdsecAppsecKey = apiAppsecKey
	}

	var tlsConfig *tls.Config
	crowdsecStreamRoute := ""
	crowdsecHeader := ""
	if config.CrowdsecMode == configuration.AloneMode {
		config.CrowdsecCapiMachineID, _ = configuration.GetVariable(config, "CrowdsecCapiMachineID")
		config.CrowdsecCapiPassword, _ = configuration.GetVariable(config, "CrowdsecCapiPassword")
		config.CrowdsecLapiScheme = configuration.HTTPS
		config.CrowdsecLapiHost = crowdsecCapiHost
		config.CrowdsecLapiPath = "/"
		config.UpdateIntervalSeconds = 7200 // 2 hours
		crowdsecStreamRoute = crowdsecCapiStreamRoute
		crowdsecHeader = crowdsecCapiHeader
	} else {
		crowdsecStreamRoute = crowdsecLapiStreamRoute
		crowdsecHeader = crowdsecLapiHeader
		tlsConfig, err = configuration.GetTLSConfigCrowdsec(config, log, false)
		if err != nil {
			log.Error("New:getTLSConfigCrowdsec fail to get tlsConfig " + err.Error())
			return nil, err
		}
		apiKey, errKey := configuration.GetVariable(config, "CrowdsecLapiKey")
		if errKey != nil && len(tlsConfig.Certificates) == 0 {
			log.Error("New:crowdsecLapiKey fail to get CrowdsecLapiKey and no client certificate setup " + errKey.Error())
			return nil, errKey
		}
		config.CrowdsecLapiKey = apiKey
		if config.CrowdsecAppsecKey == "" {
			config.CrowdsecAppsecKey = apiKey
		}
	}

	var banTemplate *template.Template
	var banTemplateContentType string
	if config.BanFilePath != "" {
		banTemplate, banTemplateContentType, _ = configuration.GetTemplate(config.BanFilePath)
	}

	bouncer := &Bouncer{
		streamLastSuccess: time.Now().UnixNano(),
		streamHealthy:     1,
		streamStartup:     1,
		next:              next,
		name:              name,
		template:          template.New("CrowdsecBouncer").Delims("[[", "]]"),

		enabled:                   config.Enabled,
		crowdsecMode:              config.CrowdsecMode,
		appsecEnabled:             config.CrowdsecAppsecEnabled,
		appsecScheme:              config.CrowdsecAppsecScheme,
		appsecHost:                config.CrowdsecAppsecHost,
		appsecPath:                config.CrowdsecAppsecPath,
		appsecKey:                 config.CrowdsecAppsecKey,
		appsecFailureBlock:        config.CrowdsecAppsecFailureBlock,
		appsecUnreachableBlock:    config.CrowdsecAppsecUnreachableBlock,
		appsecUnreadableBodyBlock: config.CrowdsecAppsecUnreadableBodyBlock,
		appsecBodyLimit:           config.CrowdsecAppsecBodyLimit,
		crowdsecScheme:            config.CrowdsecLapiScheme,
		crowdsecHost:              config.CrowdsecLapiHost,
		crowdsecPath:              config.CrowdsecLapiPath,
		crowdsecKey:               config.CrowdsecLapiKey,
		crowdsecMachineID:         config.CrowdsecCapiMachineID,
		crowdsecPassword:          config.CrowdsecCapiPassword,
		crowdsecScenarios:         config.CrowdsecCapiScenarios,
		updateInterval:            config.UpdateIntervalSeconds,
		updateMaxFailure:          config.UpdateMaxFailure,
		remediationCustomHeader:   config.RemediationHeadersCustomName,
		forwardedCustomHeader:     config.ForwardedHeadersCustomName,
		defaultDecisionTimeout:    config.DefaultDecisionSeconds,
		remediationStatusCode:     config.RemediationStatusCode,
		redisUnreachableBlock:     config.RedisCacheUnreachableBlock,
		banTemplate:               banTemplate,
		banTemplateContentType:    banTemplateContentType,
		traceCustomHeader:         config.TraceHeadersCustomName,
		crowdsecStreamRoute:       crowdsecStreamRoute,
		crowdsecHeader:            crowdsecHeader,
		log:                       log,
		serverPoolStrategy: &ip.PoolStrategy{
			Checker: serverChecker,
		},
		clientPoolStrategy: &ip.PoolStrategy{
			Checker: clientChecker,
		},
		httpClient: &http.Client{
			Transport: &http.Transport{
				MaxIdleConns:        10,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     30 * time.Second,
				TLSClientConfig:     tlsConfig,
			},
			Timeout: time.Duration(config.HTTPTimeoutSeconds) * time.Second,
		},
		httpAppsecClient: &http.Client{
			Transport: &http.Transport{
				MaxIdleConns:        10,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     30 * time.Second,
				TLSClientConfig:     tlsAppsecConfig,
			},
			Timeout: time.Duration(config.HTTPTimeoutSeconds) * time.Second,
		},
		cacheClient:   &cache.Client{},
		captchaClient: &captcha.Client{},
	}
	config.RedisCachePassword, _ = configuration.GetVariable(config, "RedisCachePassword")
	bouncer.cacheClient.NewWithACL(
		log,
		config.RedisCacheEnabled,
		config.RedisCacheHost,
		config.RedisCacheReadHosts,
		config.RedisCacheUsername,
		config.RedisCachePassword,
		config.RedisCacheDatabase,
		config.RedisCacheKeyPrefix,
	)
	if config.RedisCachePoolMaxActive != 0 {
		if poolErr := bouncer.cacheClient.ConfigurePool(config.RedisCachePoolMaxActive, config.RedisCachePoolMaxIdle, config.RedisCachePoolMaxWaiters, config.RedisCachePoolIdleTimeoutSeconds, config.RedisCachePoolMaxLifetimeSeconds); poolErr != nil {
			return nil, poolErr
		}
	}
	initialized := false
	var refreshDone <-chan struct{}
	defer func() {
		if !initialized {
			bouncer.cacheClient.Close()
			return
		}
		if config.RedisCachePoolMaxActive > 0 && ctx.Done() != nil {
			go func() {
				<-ctx.Done()
				// The retiring refresh must release its fenced lease before Redis is closed.
				if refreshDone != nil {
					<-refreshDone
				}
				bouncer.cacheClient.Close()
			}()
		}
	}()
	config.CaptchaSiteKey, _ = configuration.GetVariable(config, "CaptchaSiteKey")
	config.CaptchaSecretKey, _ = configuration.GetVariable(config, "CaptchaSecretKey")
	err = bouncer.captchaClient.New(
		log,
		bouncer.cacheClient,
		&http.Client{
			Transport: &http.Transport{MaxIdleConns: 10, MaxIdleConnsPerHost: 10, IdleConnTimeout: 30 * time.Second},
			Timeout:   time.Duration(config.HTTPTimeoutSeconds) * time.Second,
		},
		config.CaptchaProvider,
		config.CaptchaCustomJsURL,
		config.CaptchaCustomKey,
		config.CaptchaCustomResponse,
		config.CaptchaCustomValidateURL,
		config.CaptchaSiteKey,
		config.CaptchaSecretKey,
		config.RemediationHeadersCustomName,
		config.CaptchaFilePath,
		config.CaptchaGracePeriodSeconds,
	)
	if err != nil {
		log.Error("CaptchaClient not valid " + err.Error())
		return nil, err
	}
	if config.CrowdsecMode == configuration.AppsecMode {
		initialized = true
		return bouncer, nil
	}

	if config.CrowdsecMode == configuration.StreamMode || config.CrowdsecMode == configuration.AloneMode {
		if config.CrowdsecMode == configuration.AloneMode {
			if err := getToken(bouncer); err != nil {
				bouncer.log.Error("New:getToken " + err.Error())
				return nil, err
			}
		}
		if config.StreamStartupBlock {
			atomic.StoreInt32(&bouncer.streamHealthy, 0)
			handleStreamTickerContext(ctx, bouncer)
		}
		refreshDone = startContextTicker(ctx, config.UpdateIntervalSeconds, !config.StreamStartupBlock, func() {
			handleStreamTickerContext(ctx, bouncer)
		})
	}

	// Start metrics ticker if not already running
	if metricsTicker == nil && config.MetricsUpdateIntervalSeconds > 0 {
		lastMetricsPush = time.Now() // Initialize lastMetricsPush when starting the metrics ticker
		go handleMetricsTicker(bouncer)
		metricsTicker = startTicker(config.MetricsUpdateIntervalSeconds, func() {
			handleMetricsTicker(bouncer)
		})
	}

	bouncer.log.Debug("New initialized mode:" + config.CrowdsecMode)

	initialized = true
	return bouncer, nil
}

// ServeHTTP principal function of plugin.
//
//nolint:nestif
func (bouncer *Bouncer) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if !bouncer.enabled {
		bouncer.next.ServeHTTP(rw, req)
		return
	}

	// Here we check for the trusted IPs in the forwardedCustomHeader
	remoteIP, err := ip.GetRemoteIP(req, bouncer.serverPoolStrategy, bouncer.forwardedCustomHeader)
	if err != nil {
		bouncer.log.Error(fmt.Sprintf("ServeHTTP:getRemoteIp ip:%s %s", remoteIP, err.Error()))
		bouncer.handleBanServeHTTP(rw, req, remoteIP, configuration.ReasonTECH)
		return
	}
	isTrusted, err := bouncer.clientPoolStrategy.Checker.Contains(remoteIP)
	if err != nil {
		bouncer.log.Error(fmt.Sprintf("ServeHTTP:checkerContains ip:%s %s", remoteIP, err.Error()))
		bouncer.handleBanServeHTTP(rw, req, remoteIP, configuration.ReasonTECH)
		return
	}
	// if our IP is in the trusted list we bypass the next checks
	bouncer.log.Debug(fmt.Sprintf("ServeHTTP ip:%s isTrusted:%v", remoteIP, isTrusted))
	if isTrusted {
		bouncer.next.ServeHTTP(rw, req)
		return
	}

	if bouncer.crowdsecMode == configuration.AppsecMode {
		bouncer.handleNextServeHTTP(rw, req, remoteIP)
		return
	}

	// TODO This should be simplified
	if bouncer.crowdsecMode != configuration.NoneMode {
		value, cacheErr := bouncer.cacheClient.GetContext(req.Context(), remoteIP)
		if cacheErr != nil {
			cacheErrString := cacheErr.Error()
			bouncer.log.Debug(fmt.Sprintf("ServeHTTP:Get ip:%s isBanned:false %s", remoteIP, cacheErrString))
			if !bouncer.redisUnreachableBlock && cacheErrString == cache.CacheUnreachable {
				bouncer.log.Error(fmt.Sprintf("ServeHTTP:Get ip:%s redisUnreachable=true", remoteIP))
				bouncer.handleNextServeHTTP(rw, req, remoteIP)
				return
			}
			if cacheErrString != cache.CacheMiss {
				bouncer.log.Error(fmt.Sprintf("ServeHTTP:Get ip:%s %s", remoteIP, cacheErrString))
				bouncer.handleBanServeHTTP(rw, req, remoteIP, configuration.ReasonTECH)
				return
			}
		} else {
			bouncer.log.Debug(fmt.Sprintf("ServeHTTP ip:%s cache:hit isBanned:%v", remoteIP, value))
			if value == cache.NoBannedValue {
				bouncer.handleNextServeHTTP(rw, req, remoteIP)
			} else {
				bouncer.handleRemediationServeHTTP(rw, req, remoteIP, value)
			}
			return
		}
	}

	// Right here if we cannot join the stream we forbid the request to go on.
	if bouncer.crowdsecMode == configuration.StreamMode || bouncer.crowdsecMode == configuration.AloneMode {
		if atomic.LoadInt32(&bouncer.streamHealthy) == 1 || bouncer.adoptSharedSnapshot() {
			bouncer.handleNextServeHTTP(rw, req, remoteIP)
		} else {
			bouncer.log.Debug(fmt.Sprintf("ServeHTTP isCrowdsecStreamHealthy:false ip:%s updateFailure:%d", remoteIP, atomic.LoadInt64(&bouncer.updateFailures)))
			bouncer.handleBanServeHTTP(rw, req, remoteIP, configuration.ReasonTECH)
		}
	} else {
		value, err := handleNoStreamCache(bouncer, remoteIP)
		if err != nil {
			bouncer.log.Debug("handleNoStreamCache:crowdsecQuery " + err.Error())
		}
		if value == cache.NoBannedValue {
			bouncer.handleNextServeHTTP(rw, req, remoteIP)
		} else {
			bouncer.log.Debug(fmt.Sprintf("ServeHTTP:handleNoStreamCache ip:%s isBanned:%v %s", remoteIP, value, err.Error()))
			bouncer.handleRemediationServeHTTP(rw, req, remoteIP, value)
		}
	}
}

// CUSTOM CODE.
// TODO place in another file.

// Decision Body returned from Crowdsec LAPI.
type Decision struct {
	ID        int    `json:"id"`
	Origin    string `json:"origin"`
	Type      string `json:"type"`
	Scope     string `json:"scope"`
	Value     string `json:"value"`
	Duration  string `json:"duration"`
	Scenario  string `json:"scenario"`
	Simulated bool   `json:"simulated"`
}

// Stream Body returned from Crowdsec Stream LAPI.
type Stream struct {
	Deleted []Decision `json:"deleted"`
	New     []Decision `json:"new"`
}

// Login Body returned from Crowdsec Login CAPI.
type Login struct {
	Code   int    `json:"code"`
	Token  string `json:"token"`
	Expire string `json:"expire"`
}

// To append Headers we need to call rw.WriteHeader after set any header.
func (bouncer *Bouncer) handleBanServeHTTP(rw http.ResponseWriter, req *http.Request, remoteIP, reason string) {
	atomic.AddInt64(&blockedRequests, 1)

	if bouncer.remediationCustomHeader != "" {
		rw.Header().Set(bouncer.remediationCustomHeader, "ban")
	}
	rw.Header().Set("Content-Type", bouncer.banTemplateContentType)
	rw.WriteHeader(bouncer.remediationStatusCode)
	if bouncer.banTemplate == nil || req.Method == http.MethodHead {
		return
	}
	templateData := map[string]string{
		"RemediationReason": reason,
		"ClientIP":          remoteIP,
	}

	if bouncer.traceCustomHeader != "" {
		headerVal := req.Header.Get(bouncer.traceCustomHeader)

		if headerVal != "" {
			templateData["TraceID"] = headerVal
		}
	}

	err := bouncer.banTemplate.Execute(rw, templateData)

	if err != nil {
		bouncer.log.Warn("handleBanServeHTTP could not write template to ResponseWriter: " + err.Error())
	}
}

func (bouncer *Bouncer) handleRemediationServeHTTP(rw http.ResponseWriter, req *http.Request, remoteIP, remediation string) {
	bouncer.log.Debug(fmt.Sprintf("handleRemediationServeHTTP ip:%s remediation:%s", remoteIP, remediation))
	if bouncer.captchaClient.Valid && remediation == cache.CaptchaValue && req.Method != http.MethodHead {
		if bouncer.captchaClient.Check(remoteIP) {
			bouncer.handleNextServeHTTP(rw, req, remoteIP)
			return
		}
		atomic.AddInt64(&blockedRequests, 1) //  If we serve a captcha that should count as a dropped request.
		bouncer.captchaClient.ServeHTTP(rw, req, remoteIP)
		return
	}
	bouncer.handleBanServeHTTP(rw, req, remoteIP, configuration.ReasonLAPI)
}

func (bouncer *Bouncer) handleNextServeHTTP(rw http.ResponseWriter, req *http.Request, remoteIP string) {
	if bouncer.appsecEnabled {
		decision, err := appsecQuery(bouncer, remoteIP, req)
		if err != nil {
			bouncer.log.Debug(fmt.Sprintf("handleNextServeHTTP ip:%s isWaf:true %s", remoteIP, err.Error()))
			bouncer.handleAppsecErrorServeHTTP(rw, req, remoteIP, err)
			return
		}
		if bouncer.handleAppsecDecisionServeHTTP(rw, req, remoteIP, decision) {
			return
		}
		if strings.HasPrefix(req.URL.Path, appsecChallengePathPrefix) {
			http.NotFound(rw, req)
			return
		}
	}
	bouncer.next.ServeHTTP(rw, req)
}

func (bouncer *Bouncer) handleAppsecDecisionServeHTTP(rw http.ResponseWriter, req *http.Request, remoteIP string, decision *AppSecResponse) bool {
	switch {
	case decision == nil || decision.Action == appsecAllowAction:
		return false
	case decision.Action == appsecChallengeAction:
		bouncer.handleAppsecResponseServeHTTP(rw, req, decision)
	case decision.Action == appsecCaptchaAction && bouncer.captchaClient.Valid && req.Method != http.MethodHead:
		if bouncer.captchaClient.Check(remoteIP) {
			return false
		}
		atomic.AddInt64(&blockedRequests, 1)
		bouncer.captchaClient.ServeHTTP(rw, req, remoteIP)
	default:
		bouncer.handleBanServeHTTP(rw, req, remoteIP, configuration.ReasonAPPSEC)
	}
	return true
}

func (bouncer *Bouncer) handleAppsecErrorServeHTTP(rw http.ResponseWriter, req *http.Request, remoteIP string, err error) {
	switch {
	case !errors.Is(err, errAppsecGetBody):
		bouncer.handleBanServeHTTP(rw, req, remoteIP, configuration.ReasonAPPSEC)
	case req.Context().Err() != nil:
		rw.WriteHeader(statusClientClosedRequest)
	default:
		rw.WriteHeader(http.StatusBadRequest)
	}
}

func (bouncer *Bouncer) handleAppsecResponseServeHTTP(rw http.ResponseWriter, req *http.Request, decision *AppSecResponse) {
	if !strings.HasPrefix(req.URL.Path, appsecChallengePathPrefix) {
		atomic.AddInt64(&blockedRequests, 1)
	}

	for name, values := range decision.UserHeaders {
		rw.Header().Del(name)
		for _, value := range values {
			rw.Header().Add(name, value)
		}
	}
	for _, cookie := range decision.UserCookies {
		rw.Header().Add("Set-Cookie", cookie)
	}
	if bouncer.remediationCustomHeader != "" {
		rw.Header().Set(bouncer.remediationCustomHeader, "challenge")
	}
	rw.WriteHeader(decision.HTTPStatus)

	if req.Method == http.MethodHead {
		return
	}
	if _, err := rw.Write([]byte(decision.UserBodyContent)); err != nil {
		bouncer.log.Warn("handleAppsecResponseServeHTTP could not write appsec response: " + err.Error())
	}
}

// A cold follower can miss every success marker when refresh timers align.
// Adopt a committed snapshot on an uncached request instead of waiting one poll.
func (bouncer *Bouncer) adoptSharedSnapshot() bool {
	fresh, err := bouncer.cacheClient.HasFreshSnapshot()
	if err != nil || !fresh {
		return false
	}
	atomic.StoreInt32(&bouncer.streamStartup, 0)
	atomic.StoreInt64(&bouncer.streamLastSuccess, time.Now().UnixNano())
	atomic.StoreInt32(&bouncer.streamHealthy, 1)
	atomic.StoreInt64(&bouncer.updateFailures, 0)
	return true
}

func handleStreamTicker(bouncer *Bouncer) {
	handleStreamTickerContext(context.Background(), bouncer)
}

func handleStreamTickerContext(ctx context.Context, bouncer *Bouncer) {
	if err := handleStreamCacheContext(ctx, bouncer); err != nil {
		if ctx.Err() != nil {
			return
		}
		if errors.Is(err, cache.ErrRefreshBusy) {
			bouncer.expireStreamHealth()
			return
		}
		failures := atomic.LoadInt64(&bouncer.updateFailures)
		healthy := atomic.LoadInt32(&bouncer.streamHealthy) == 1
		bouncer.log.Warn(fmt.Sprintf("handleStreamTicker updateFailure:%d isCrowdsecStreamHealthy:%t %s", failures, healthy, err.Error()))
		if bouncer.updateMaxFailure != -1 && failures >= bouncer.updateMaxFailure && healthy {
			atomic.StoreInt32(&bouncer.streamHealthy, 0)
			bouncer.log.Error(fmt.Sprintf("handleStreamTicker:error updateFailure:%d %s", failures, err.Error()))
		}
		atomic.AddInt64(&bouncer.updateFailures, 1)
	} else {
		atomic.StoreInt64(&bouncer.streamLastSuccess, time.Now().UnixNano())
		atomic.StoreInt32(&bouncer.streamHealthy, 1)
		atomic.StoreInt64(&bouncer.updateFailures, 0)
	}
}

// A busy owner is not a failure, but cannot keep stale followers healthy forever.
func (bouncer *Bouncer) expireStreamHealth() {
	if bouncer.updateMaxFailure == -1 {
		return
	}
	lastSuccess := atomic.LoadInt64(&bouncer.streamLastSuccess)
	limit := cache.RefreshLeaseDuration + time.Duration(bouncer.updateMaxFailure+1)*time.Duration(bouncer.updateInterval)*time.Second
	if lastSuccess > 0 && time.Since(time.Unix(0, lastSuccess)) > limit {
		atomic.StoreInt32(&bouncer.streamHealthy, 0)
	}
}

func startContextTicker(ctx context.Context, interval int64, immediate bool, work func()) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(time.Duration(interval) * time.Second)
		defer ticker.Stop()
		if immediate && ctx.Err() == nil {
			work()
		}
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if ctx.Err() == nil {
					work()
				}
			}
		}
	}()
	return done
}

func handleMetricsTicker(bouncer *Bouncer) {
	if err := reportMetrics(bouncer); err != nil {
		bouncer.log.Error("handleMetricsTicker:reportMetrics " + err.Error())
	}
}

func startTicker(updateInterval int64, work func()) *time.Ticker {
	ticker := time.NewTicker(time.Duration(updateInterval) * time.Second)
	go runTicker(ticker.C, work)
	return ticker
}

func runTicker(ticks <-chan time.Time, work func()) {
	for range ticks {
		go work()
	}
}

// We are now in none or live mode.
func handleNoStreamCache(bouncer *Bouncer, remoteIP string) (string, error) {
	isLiveMode := bouncer.crowdsecMode == configuration.LiveMode
	routeURL := url.URL{
		Scheme:   bouncer.crowdsecScheme,
		Host:     bouncer.crowdsecHost,
		Path:     bouncer.crowdsecPath + crowdsecLapiRoute,
		RawQuery: fmt.Sprintf("ip=%v", remoteIP),
	}
	body, err := crowdsecQuery(bouncer, routeURL.String(), nil)
	if err != nil {
		if bouncer.updateMaxFailure == -1 {
			return cache.NoBannedValue, err
		}
		return cache.BannedValue, err
	}

	var decisions []Decision
	err = json.Unmarshal(body, &decisions)
	if err != nil {
		return cache.BannedValue, fmt.Errorf("handleNoStreamCache:parseBody %w", err)
	}
	var decision Decision
	var duration time.Duration
	for _, d := range decisions {
		remaining, parseErr := time.ParseDuration(d.Duration)
		if parseErr != nil {
			return cache.BannedValue, fmt.Errorf("handleNoStreamCache:parseDuration %w", parseErr)
		}
		// Expired decisions must neither win remediation selection nor enter the cache.
		if remaining <= 0 {
			continue
		}
		decision = d
		duration = remaining
		if decision.Type == "ban" {
			break
		}
	}
	if duration == 0 {
		if isLiveMode {
			if err = bouncer.cacheClient.Set(remoteIP, cache.NoBannedValue, bouncer.defaultDecisionTimeout); err != nil {
				return cache.BannedValue, err
			}
		}
		return cache.NoBannedValue, nil
	}
	var value string
	switch decision.Type {
	case "ban":
		value = cache.BannedValue
	case "captcha":
		value = cache.CaptchaValue
	default:
		bouncer.log.Info("handleStreamCache:unknownType " + decision.Type)
		value = cache.BannedValue
	}
	if isLiveMode && bouncer.defaultDecisionTimeout > 0 {
		durationSecond := int64(duration.Seconds())
		if bouncer.defaultDecisionTimeout < durationSecond {
			durationSecond = bouncer.defaultDecisionTimeout
		}
		if err = bouncer.cacheClient.Set(remoteIP, value, durationSecond); err != nil {
			return cache.BannedValue, err
		}
	}
	return value, errors.New("handleNoStreamCache:banned")
}

func getToken(bouncer *Bouncer) error {
	loginURL := url.URL{
		Scheme: bouncer.crowdsecScheme,
		Host:   bouncer.crowdsecHost,
		Path:   crowdsecCapiLoginRoute,
	}

	// Move the login-specific payload here
	loginData := []byte(fmt.Sprintf(
		`{"machine_id": "%v","password": "%v","scenarios": ["%v"]}`,
		bouncer.crowdsecMachineID,
		bouncer.crowdsecPassword,
		strings.Join(bouncer.crowdsecScenarios, `","`),
	))

	body, err := crowdsecQuery(bouncer, loginURL.String(), loginData)
	if err != nil {
		return err
	}
	var login Login
	err = json.Unmarshal(body, &login)
	if err != nil {
		return fmt.Errorf("getToken:parseBody %w", err)
	}
	if login.Code == http.StatusOK && len(login.Token) > 0 {
		bouncer.crowdsecKey = login.Token
		return nil
	}
	bouncer.log.Warn(fmt.Sprintf("getToken statusCode:%d", login.Code))
	return fmt.Errorf("getToken statusCode:%d", login.Code)
}

func decodeStreamSnapshot(body []byte) (Stream, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		return Stream{}, fmt.Errorf("handleStreamCache:parseBody %w", err)
	}
	if fields == nil {
		return Stream{}, errors.New("handleStreamCache:expected snapshot object")
	}
	if _, ok := fields["new"]; !ok {
		return Stream{}, errors.New("handleStreamCache:missing new field")
	}
	if _, ok := fields["deleted"]; !ok {
		return Stream{}, errors.New("handleStreamCache:missing deleted field")
	}
	// Explicit null lists are valid empty lists in the CrowdSec API.
	var stream Stream
	if err := json.Unmarshal(body, &stream); err != nil {
		return Stream{}, fmt.Errorf("handleStreamCache:parseBody %w", err)
	}
	return stream, nil
}

func handleStreamCache(bouncer *Bouncer) error {
	return handleStreamCacheContext(context.Background(), bouncer)
}

func handleStreamCacheContext(ctx context.Context, bouncer *Bouncer) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	token, err := bouncer.cacheClient.BeginRefresh()
	if err != nil {
		return err
	}
	if token == "" {
		atomic.StoreInt32(&bouncer.streamStartup, 0)
		return nil
	}
	defer func() {
		if releaseErr := bouncer.cacheClient.EndRefresh(token); releaseErr != nil {
			bouncer.log.Warn("handleStreamCache:release " + releaseErr.Error())
		}
	}()
	markerTTL := bouncer.updateInterval - 1
	if markerTTL < 1 {
		markerTTL = 1
	}
	streamURL := url.URL{Scheme: bouncer.crowdsecScheme, Host: bouncer.crowdsecHost,
		Path: bouncer.crowdsecPath + bouncer.crowdsecStreamRoute, RawQuery: "startup=true"}
	body, err := crowdsecQueryContext(ctx, bouncer, streamURL.String(), nil)
	if err != nil {
		return err
	}
	stream, err := decodeStreamSnapshot(body)
	if err != nil {
		return err
	}
	entries := make(map[string]cache.SnapshotEntry)
	removed := make([]string, 0, len(stream.Deleted))
	for _, decision := range stream.Deleted {
		removed = append(removed, decision.Value)
	}
	now := time.Now()
	for _, decision := range stream.New {
		duration, parseErr := time.ParseDuration(decision.Duration)
		if parseErr != nil {
			return fmt.Errorf("handleStreamCache:duration %w", parseErr)
		}
		if duration <= 0 {
			continue
		}
		value := cache.BannedValue
		if decision.Type == "captcha" {
			value = cache.CaptchaValue
		}
		// A solved CAPTCHA must not bypass a simultaneous ban for the same IP.
		if previous, ok := entries[decision.Value]; ok && previous.Value == cache.BannedValue && value == cache.CaptchaValue {
			continue
		}
		entries[decision.Value] = cache.SnapshotEntry{Value: value, Until: now.Add(duration).UnixMilli()}
	}
	if err = bouncer.cacheClient.CommitRefreshContext(ctx, token, entries, removed, markerTTL); err != nil {
		return err
	}
	atomic.StoreInt32(&bouncer.streamStartup, 0)
	return nil
}

func isReverseProxyError(statusCode int) bool {
	return statusCode == http.StatusBadGateway ||
		statusCode == http.StatusServiceUnavailable ||
		statusCode == http.StatusGatewayTimeout
}

func crowdsecQuery(bouncer *Bouncer, stringURL string, data []byte) ([]byte, error) {
	return crowdsecQueryContext(context.Background(), bouncer, stringURL, data)
}

func crowdsecQueryContext(ctx context.Context, bouncer *Bouncer, stringURL string, data []byte) ([]byte, error) {
	var req *http.Request
	if len(data) > 0 {
		req, _ = http.NewRequest(http.MethodPost, stringURL, bytes.NewBuffer(data))
	} else {
		req, _ = http.NewRequest(http.MethodGet, stringURL, nil)
	}
	req = req.WithContext(ctx)
	req.Header.Set(bouncer.crowdsecHeader, bouncer.crowdsecKey)
	req.Header.Set("User-Agent", "Crowdsec-Bouncer-Traefik-Plugin/"+pluginVersion)

	res, err := bouncer.httpClient.Do(req)
	if err != nil || isReverseProxyError(res.StatusCode) {
		return nil, fmt.Errorf("crowdsecQuery:unreachable url:%s %w", stringURL, err)
	}
	defer func() {
		if err = res.Body.Close(); err != nil {
			bouncer.log.Error("crowdsecQuery:closeBody " + err.Error())
		}
	}()
	if res.StatusCode == http.StatusUnauthorized && bouncer.crowdsecMode == configuration.AloneMode {
		if errToken := getToken(bouncer); errToken != nil {
			return nil, fmt.Errorf("crowdsecQuery:renewToken url:%s %w", stringURL, errToken)
		}
		return crowdsecQueryContext(ctx, bouncer, stringURL, nil)
	}

	// Check if the status code starts with 2
	statusStr := strconv.Itoa(res.StatusCode)
	if len(statusStr) < 1 || statusStr[0] != '2' {
		return nil, fmt.Errorf("crowdsecQuery method:%s url:%s, statusCode:%d (expected: 2xx)", req.Method, stringURL, res.StatusCode)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("crowdsecQuery:readBody %w", err)
	}
	return body, nil
}

// isBodyUnreadable reports whether the request body cannot be buffered before
// forwarding it to the Appsec component. An HTTP/2 or HTTP/3 request without a
// Content-Length (typically a bidirectional gRPC stream) keeps its body open
// for the whole life of the stream and never reaches EOF, so reading it with
// io.ReadAll would block until the request times out and is wrongly turned into
// a 403. This mirrors the reference lua-cs-bouncer behavior, which refuses to
// read the body of an HTTP/2+ request that has no Content-Length.
func isBodyUnreadable(httpReq *http.Request) bool {
	return httpReq.Body != nil && httpReq.Body != http.NoBody && httpReq.ProtoMajor >= 2 && httpReq.ContentLength < 0
}

// isMethodWithBody used only when isBodyUnreadable returns true but the request method can't have body.
func isMethodWithBody(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
		return true
	default:
		return false
	}
}

//nolint:nilnil,gocyclo,funlen,gocognit
func appsecQuery(bouncer *Bouncer, ip string, httpReq *http.Request) (*AppSecResponse, error) {
	routeURL := url.URL{
		Scheme: bouncer.appsecScheme,
		Host:   bouncer.appsecHost,
		Path:   bouncer.appsecPath,
	}
	var req *http.Request
	switch {
	case isBodyUnreadable(httpReq):
		if bouncer.appsecUnreadableBodyBlock && isMethodWithBody(httpReq.Method) {
			return nil, errors.New("appsecQuery:unreadableBody dropped")
		}
		req, _ = http.NewRequest(http.MethodGet, routeURL.String(), nil)
	case bouncer.appsecBodyLimit > 0 && httpReq.Body != nil:
		var bodyBuffer bytes.Buffer
		limitedReader := io.LimitReader(httpReq.Body, bouncer.appsecBodyLimit)
		teeReader := io.TeeReader(limitedReader, &bodyBuffer)
		bodyBytes, err := io.ReadAll(teeReader)
		if err != nil {
			return nil, fmt.Errorf("%w %w", errAppsecGetBody, err)
		}
		// Conserve body intact after reading it for other middlewares and service
		httpReq.Body = io.NopCloser(io.MultiReader(&bodyBuffer, httpReq.Body))
		req, _ = http.NewRequest(http.MethodPost, routeURL.String(), bytes.NewBuffer(bodyBytes))
	default:
		req, _ = http.NewRequest(http.MethodGet, routeURL.String(), nil)
	}

	for key, headers := range httpReq.Header {
		for _, value := range headers {
			req.Header.Add(key, value)
		}
	}
	req.Header.Set(crowdsecAppsecHeader, bouncer.appsecKey)
	req.Header.Set(crowdsecAppsecIPHeader, ip)
	req.Header.Set(crowdsecAppsecVerbHeader, httpReq.Method)
	req.Header.Set(crowdsecAppsecHostHeader, httpReq.Host)
	req.Header.Set(crowdsecAppsecURIHeader, httpReq.URL.String())
	req.Header.Set(crowdsecAppsecUserAgent, httpReq.Header.Get("User-Agent"))
	if httpReq.ProtoMajor > 0 {
		req.Header.Set(crowdsecAppsecHTTPVersionHeader, fmt.Sprintf("%d%d", httpReq.ProtoMajor, httpReq.ProtoMinor))
	}
	req.Header.Set("User-Agent", "Crowdsec-Bouncer-Traefik-Plugin/"+pluginVersion)

	res, err := bouncer.httpAppsecClient.Do(req)
	if err != nil || isReverseProxyError(res.StatusCode) {
		bouncer.log.Error("appsecQuery:unreachable")
		if bouncer.appsecUnreachableBlock {
			return nil, fmt.Errorf("appsecQuery:unreachable %w", err)
		}
		return nil, nil
	}
	defer func() {
		// net/http returns a conn to the idle pool once its body has been read to EOF, closing early discards it.
		// Drain the body from the non-200 paths, which return earlier, keep their connections too.
		if _, errDrain := io.Copy(io.Discard, res.Body); errDrain != nil {
			bouncer.log.Debug("appsecQuery:drainBody " + errDrain.Error())
		}
		if errClose := res.Body.Close(); errClose != nil {
			bouncer.log.Error("appsecQuery:closeBody " + errClose.Error())
		}
	}()
	switch res.StatusCode {
	case http.StatusInternalServerError:
		bouncer.log.Info("appsecQuery:failure")
		if bouncer.appsecFailureBlock {
			return nil, errors.New("appsecQuery:failure statusCode:500")
		}
		return nil, nil
	case http.StatusOK:
		return nil, nil
	case http.StatusForbidden:
		body, err := io.ReadAll(io.LimitReader(res.Body, appsecResponseBodyLimit+1))
		if err != nil {
			return nil, fmt.Errorf("appsecQuery:readBody %w", err)
		}
		if int64(len(body)) > appsecResponseBodyLimit {
			bouncer.log.Debug("appsecQuery:responseBodyTooLarge")
			return nil, errors.New("appsecQuery:responseBodyTooLarge statusCode:403")
		}
		body = bytes.TrimSpace(body)
		if len(body) == 0 {
			return nil, errors.New("appsecQuery:responseBodyMissing statusCode:403")
		}

		var decision AppSecResponse
		if err := json.Unmarshal(body, &decision); err != nil {
			return nil, fmt.Errorf("appsecQuery:parseBody %w", err)
		}
		if decision.Action == "" || decision.HTTPStatus == 0 {
			return nil, errors.New("appsecQuery:responseAppsecKeysMissing")
		}
		if decision.Action == appsecChallengeAction && decision.UserBodyContent == "" {
			return nil, errors.New("appsecQuery:challengeBodyMissing")
		}
		return &decision, nil
	default:
		bouncer.log.Info(fmt.Sprintf("appsecQuery:unexpectedStatus statusCode:%d", res.StatusCode))
		return nil, fmt.Errorf("appsecQuery: statusCode:%d", res.StatusCode)
	}
}

func reportMetrics(bouncer *Bouncer) error {
	now := time.Now()
	currentCount := atomic.LoadInt64(&blockedRequests)
	windowSizeSeconds := int(now.Sub(lastMetricsPush).Seconds())

	bouncer.log.Debug(fmt.Sprintf("reportMetrics: blocked_requests=%d window_size=%ds", currentCount, windowSizeSeconds))

	metrics := map[string]interface{}{
		"remediation_components": []map[string]interface{}{
			{
				"version": pluginVersion,
				"type":    "bouncer",
				"name":    "traefik_plugin",
				"metrics": []map[string]interface{}{
					{
						"items": []map[string]interface{}{
							{
								"name":  "dropped",
								"value": currentCount,
								"unit":  "request",
								"labels": map[string]string{
									"type": "traefik_plugin",
								},
							},
						},
						"meta": map[string]interface{}{
							"window_size_seconds": windowSizeSeconds,
							"utc_now_timestamp":   now.Unix(),
						},
					},
				},
				"utc_startup_timestamp": time.Now().Unix(),
				"feature_flags":         []string{},
				"os": map[string]string{
					"name":    "unknown",
					"version": "unknown",
				},
			},
		},
	}

	data, err := json.Marshal(metrics)
	if err != nil {
		return fmt.Errorf("reportMetrics:marshal %w", err)
	}

	metricsURL := url.URL{
		Scheme: bouncer.crowdsecScheme,
		Host:   bouncer.crowdsecHost,
		Path:   bouncer.crowdsecPath + crowdsecLapiMetricsRoute,
	}

	_, err = crowdsecQuery(bouncer, metricsURL.String(), data)
	if err != nil {
		return fmt.Errorf("reportMetrics:query %w", err)
	}

	atomic.StoreInt64(&blockedRequests, 0)
	lastMetricsPush = now
	return nil
}
