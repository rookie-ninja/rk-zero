// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

// Package rkzero an implementation of rkentry.Entry which could be used start restful server with go-zero framework
package rkzero

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rookie-ninja/rk-common/common"
	"github.com/rookie-ninja/rk-entry/entry"
	"github.com/rookie-ninja/rk-prom"
	"github.com/rookie-ninja/rk-query"
	"github.com/rookie-ninja/rk-zero/interceptor/auth"
	"github.com/rookie-ninja/rk-zero/interceptor/cors"
	"github.com/rookie-ninja/rk-zero/interceptor/csrf"
	"github.com/rookie-ninja/rk-zero/interceptor/jwt"
	"github.com/rookie-ninja/rk-zero/interceptor/log/zap"
	"github.com/rookie-ninja/rk-zero/interceptor/meta"
	"github.com/rookie-ninja/rk-zero/interceptor/metrics/prom"
	"github.com/rookie-ninja/rk-zero/interceptor/panic"
	"github.com/rookie-ninja/rk-zero/interceptor/ratelimit"
	"github.com/rookie-ninja/rk-zero/interceptor/secure"
	"github.com/rookie-ninja/rk-zero/interceptor/timeout"
	"github.com/rookie-ninja/rk-zero/interceptor/tracing/telemetry"
	"github.com/tal-tech/go-zero/rest"
	"go.opentelemetry.io/otel/exporters/jaeger"
	"go.opentelemetry.io/otel/sdk/trace"
	"go.uber.org/zap"
	"net/http"
	"path"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	// ZeroEntryType type of entry
	ZeroEntryType = "ZeroEntry"
	// ZeroEntryDescription description of entry
	ZeroEntryDescription = "Internal RK entry which helps to bootstrap with go-zero framework."
)

// This must be declared in order to register registration function into rk context
// otherwise, rk-boot won't able to bootstrap zero entry automatically from boot config file
func init() {
	rkentry.RegisterEntryRegFunc(RegisterZeroEntriesWithConfig)
}

// BootConfigZero boot config which is for zero entry.
//
// 1: Zero.Enabled: Enable zero entry, default is true.
// 2: Zero.Name: Name of zero entry, should be unique globally.
// 3: Zero.Port: Port of zero entry.
// 4: Zero.Cert.Ref: Reference of rkentry.CertEntry.
// 5: Zero.SW: See BootConfigSW for details.
// 6: Zero.CommonService: See BootConfigCommonService for details.
// 7: Zero.TV: See BootConfigTv for details.
// 8: Zero.Prom: See BootConfigProm for details.
// 9: Zero.Interceptors.LoggingZap.Enabled: Enable zap logging interceptor.
// 10: Zero.Interceptors.MetricsProm.Enable: Enable prometheus interceptor.
// 11: Zero.Interceptors.auth.Enabled: Enable basic auth.
// 12: Zero.Interceptors.auth.Basic: Credential for basic auth, scheme: <user:pass>
// 13: Zero.Interceptors.auth.ApiKey: Credential for X-API-Key.
// 14: Zero.Interceptors.auth.igorePrefix: List of paths that will be ignored.
// 15: Zero.Interceptors.Extension.Enabled: Enable extension interceptor.
// 16: Zero.Interceptors.Extension.Prefix: Prefix of extension header key.
// 17: Zero.Interceptors.TracingTelemetry.Enabled: Enable tracing interceptor with opentelemetry.
// 18: Zero.Interceptors.TracingTelemetry.Exporter.File.Enabled: Enable file exporter which support type of stdout and local file.
// 19: Zero.Interceptors.TracingTelemetry.Exporter.File.OutputPath: Output path of file exporter, stdout and file path is supported.
// 20: Zero.Interceptors.TracingTelemetry.Exporter.Jaeger.Enabled: Enable jaeger exporter.
// 21: Zero.Interceptors.TracingTelemetry.Exporter.Jaeger.AgentEndpoint: Specify jeager agent endpoint, localhost:6832 would be used by default.
// 22: Zero.Interceptors.RateLimit.Enabled: Enable rate limit interceptor.
// 23: Zero.Interceptors.RateLimit.Algorithm: Algorithm of rate limiter.
// 24: Zero.Interceptors.RateLimit.ReqPerSec: Request per second.
// 25: Zero.Interceptors.RateLimit.Paths.path: Name of full path.
// 26: Zero.Interceptors.RateLimit.Paths.ReqPerSec: Request per second by path.
// 27: Zero.Interceptors.Timeout.Enabled: Enable timeout interceptor.
// 28: Zero.Interceptors.Timeout.TimeoutMs: Timeout in milliseconds.
// 29: Zero.Interceptors.Timeout.Paths.path: Name of full path.
// 30: Zero.Interceptors.Timeout.Paths.TimeoutMs: Timeout in milliseconds by path.
// 31: Zero.Logger.ZapLogger.Ref: Zap logger reference, see rkentry.ZapLoggerEntry for details.
// 32: Zero.Logger.EventLogger.Ref: Event logger reference, see rkentry.EventLoggerEntry for details.
type BootConfigZero struct {
	Zero []struct {
		Enabled     bool   `yaml:"enabled" json:"enabled"`
		Name        string `yaml:"name" json:"name"`
		Port        uint64 `yaml:"port" json:"port"`
		Description string `yaml:"description" json:"description"`
		Cert        struct {
			Ref string `yaml:"ref" json:"ref"`
		} `yaml:"cert" json:"cert"`
		SW            BootConfigSw            `yaml:"sw" json:"sw"`
		CommonService BootConfigCommonService `yaml:"commonService" json:"commonService"`
		TV            BootConfigTv            `yaml:"tv" json:"tv"`
		Prom          BootConfigProm          `yaml:"prom" json:"prom"`
		Interceptors  struct {
			LoggingZap struct {
				Enabled                bool     `yaml:"enabled" json:"enabled"`
				ZapLoggerEncoding      string   `yaml:"zapLoggerEncoding" json:"zapLoggerEncoding"`
				ZapLoggerOutputPaths   []string `yaml:"zapLoggerOutputPaths" json:"zapLoggerOutputPaths"`
				EventLoggerEncoding    string   `yaml:"eventLoggerEncoding" json:"eventLoggerEncoding"`
				EventLoggerOutputPaths []string `yaml:"eventLoggerOutputPaths" json:"eventLoggerOutputPaths"`
			} `yaml:"loggingZap" json:"loggingZap"`
			MetricsProm struct {
				Enabled bool `yaml:"enabled" json:"enabled"`
			} `yaml:"metricsProm" json:"metricsProm"`
			Auth struct {
				Enabled      bool     `yaml:"enabled" json:"enabled"`
				IgnorePrefix []string `yaml:"ignorePrefix" json:"ignorePrefix"`
				Basic        []string `yaml:"basic" json:"basic"`
				ApiKey       []string `yaml:"apiKey" json:"apiKey"`
			} `yaml:"auth" json:"auth"`
			Cors struct {
				Enabled          bool     `yaml:"enabled" json:"enabled"`
				AllowOrigins     []string `yaml:"allowOrigins" json:"allowOrigins"`
				AllowCredentials bool     `yaml:"allowCredentials" json:"allowCredentials"`
				AllowHeaders     []string `yaml:"allowHeaders" json:"allowHeaders"`
				AllowMethods     []string `yaml:"allowMethods" json:"allowMethods"`
				ExposeHeaders    []string `yaml:"exposeHeaders" json:"exposeHeaders"`
				MaxAge           int      `yaml:"maxAge" json:"maxAge"`
			} `yaml:"cors" json:"cors"`
			Meta struct {
				Enabled bool   `yaml:"enabled" json:"enabled"`
				Prefix  string `yaml:"prefix" json:"prefix"`
			} `yaml:"meta" json:"meta"`
			Jwt struct {
				Enabled      bool     `yaml:"enabled" json:"enabled"`
				IgnorePrefix []string `yaml:"ignorePrefix" json:"ignorePrefix"`
				SigningKey   string   `yaml:"signingKey" json:"signingKey"`
				SigningKeys  []string `yaml:"signingKeys" json:"signingKeys"`
				SigningAlgo  string   `yaml:"signingAlgo" json:"signingAlgo"`
				TokenLookup  string   `yaml:"tokenLookup" json:"tokenLookup"`
				AuthScheme   string   `yaml:"authScheme" json:"authScheme"`
			} `yaml:"jwt" json:"jwt"`
			Secure struct {
				Enabled               bool     `yaml:"enabled" json:"enabled"`
				IgnorePrefix          []string `yaml:"ignorePrefix" json:"ignorePrefix"`
				XssProtection         string   `yaml:"xssProtection" json:"xssProtection"`
				ContentTypeNosniff    string   `yaml:"contentTypeNosniff" json:"contentTypeNosniff"`
				XFrameOptions         string   `yaml:"xFrameOptions" json:"xFrameOptions"`
				HstsMaxAge            int      `yaml:"hstsMaxAge" json:"hstsMaxAge"`
				HstsExcludeSubdomains bool     `yaml:"hstsExcludeSubdomains" json:"hstsExcludeSubdomains"`
				HstsPreloadEnabled    bool     `yaml:"hstsPreloadEnabled" json:"hstsPreloadEnabled"`
				ContentSecurityPolicy string   `yaml:"contentSecurityPolicy" json:"contentSecurityPolicy"`
				CspReportOnly         bool     `yaml:"cspReportOnly" json:"cspReportOnly"`
				ReferrerPolicy        string   `yaml:"referrerPolicy" json:"referrerPolicy"`
			} `yaml:"secure" json:"secure"`
			Csrf struct {
				Enabled        bool     `yaml:"enabled" json:"enabled"`
				IgnorePrefix   []string `yaml:"ignorePrefix" json:"ignorePrefix"`
				TokenLength    int      `yaml:"tokenLength" json:"tokenLength"`
				TokenLookup    string   `yaml:"tokenLookup" json:"tokenLookup"`
				CookieName     string   `yaml:"cookieName" json:"cookieName"`
				CookieDomain   string   `yaml:"cookieDomain" json:"cookieDomain"`
				CookiePath     string   `yaml:"cookiePath" json:"cookiePath"`
				CookieMaxAge   int      `yaml:"cookieMaxAge" json:"cookieMaxAge"`
				CookieHttpOnly bool     `yaml:"cookieHttpOnly" json:"cookieHttpOnly"`
				CookieSameSite string   `yaml:"cookieSameSite" json:"cookieSameSite"`
			} `yaml:"csrf" yaml:"csrf"`
			Gzip struct {
				Enabled bool   `yaml:"enabled" json:"enabled"`
				Level   string `yaml:"level" json:"level"`
			} `yaml:"gzip" json:"gzip"`
			RateLimit struct {
				Enabled   bool   `yaml:"enabled" json:"enabled"`
				Algorithm string `yaml:"algorithm" json:"algorithm"`
				ReqPerSec int    `yaml:"reqPerSec" json:"reqPerSec"`
				Paths     []struct {
					Path      string `yaml:"path" json:"path"`
					ReqPerSec int    `yaml:"reqPerSec" json:"reqPerSec"`
				} `yaml:"paths" json:"paths"`
			} `yaml:"rateLimit" json:"rateLimit"`
			Timeout struct {
				Enabled   bool `yaml:"enabled" json:"enabled"`
				TimeoutMs int  `yaml:"timeoutMs" json:"timeoutMs"`
				Paths     []struct {
					Path      string `yaml:"path" json:"path"`
					TimeoutMs int    `yaml:"timeoutMs" json:"timeoutMs"`
				} `yaml:"paths" json:"paths"`
			} `yaml:"timeout" json:"timeout"`
			TracingTelemetry struct {
				Enabled  bool `yaml:"enabled" json:"enabled"`
				Exporter struct {
					File struct {
						Enabled    bool   `yaml:"enabled" json:"enabled"`
						OutputPath string `yaml:"outputPath" json:"outputPath"`
					} `yaml:"file" json:"file"`
					Jaeger struct {
						Agent struct {
							Enabled bool   `yaml:"enabled" json:"enabled"`
							Host    string `yaml:"host" json:"host"`
							Port    int    `yaml:"port" json:"port"`
						} `yaml:"agent" json:"agent"`
						Collector struct {
							Enabled  bool   `yaml:"enabled" json:"enabled"`
							Endpoint string `yaml:"endpoint" json:"endpoint"`
							Username string `yaml:"username" json:"username"`
							Password string `yaml:"password" json:"password"`
						} `yaml:"collector" json:"collector"`
					} `yaml:"jaeger" json:"jaeger"`
				} `yaml:"exporter" json:"exporter"`
			} `yaml:"tracingTelemetry" json:"tracingTelemetry"`
		} `yaml:"interceptors" json:"interceptors"`
		Logger struct {
			ZapLogger struct {
				Ref string `yaml:"ref" json:"ref"`
			} `yaml:"zapLogger" json:"zapLogger"`
			EventLogger struct {
				Ref string `yaml:"ref" json:"ref"`
			} `yaml:"eventLogger" json:"eventLogger"`
		} `yaml:"logger" json:"logger"`
	} `yaml:"zero" json:"zero"`
}

// ZeroEntry implements rkentry.Entry interface.
type ZeroEntry struct {
	EntryName          string                    `json:"entryName" yaml:"entryName"`
	EntryType          string                    `json:"entryType" yaml:"entryType"`
	EntryDescription   string                    `json:"-" yaml:"-"`
	ZapLoggerEntry     *rkentry.ZapLoggerEntry   `json:"-" yaml:"-"`
	EventLoggerEntry   *rkentry.EventLoggerEntry `json:"-" yaml:"-"`
	Port               uint64                    `json:"port" yaml:"port"`
	CertEntry          *rkentry.CertEntry        `json:"-" yaml:"-"`
	SwEntry            *SwEntry                  `json:"-" yaml:"-"`
	CommonServiceEntry *CommonServiceEntry       `json:"-" yaml:"-"`
	Server             *rest.Server              `json:"-" yaml:"-"`
	ServerConf         *rest.RestConf            `json:"-" yaml:"-"`
	ServerRunOption    []rest.RunOption          `json:"-" yaml:"-"`
	TlsConfig          *tls.Config               `json:"-" yaml:"-"`
	Interceptors       []rest.Middleware         `json:"-" yaml:"-"`
	PromEntry          *PromEntry                `json:"-" yaml:"-"`
	TvEntry            *TvEntry                  `json:"-" yaml:"-"`
}

// ZeroEntryOption zero entry option.
type ZeroEntryOption func(*ZeroEntry)

// WithNameZero provide name.
func WithNameZero(name string) ZeroEntryOption {
	return func(entry *ZeroEntry) {
		entry.EntryName = name
	}
}

// WithDescriptionZero provide name.
func WithDescriptionZero(description string) ZeroEntryOption {
	return func(entry *ZeroEntry) {
		entry.EntryDescription = description
	}
}

// WithPortZero provide port.
func WithPortZero(port uint64) ZeroEntryOption {
	return func(entry *ZeroEntry) {
		entry.Port = port
	}
}

// WithZapLoggerEntryZero provide rkentry.ZapLoggerEntry.
func WithZapLoggerEntryZero(zapLogger *rkentry.ZapLoggerEntry) ZeroEntryOption {
	return func(entry *ZeroEntry) {
		entry.ZapLoggerEntry = zapLogger
	}
}

// WithEventLoggerEntryZero provide rkentry.EventLoggerEntry.
func WithEventLoggerEntryZero(eventLogger *rkentry.EventLoggerEntry) ZeroEntryOption {
	return func(entry *ZeroEntry) {
		entry.EventLoggerEntry = eventLogger
	}
}

// WithCertEntryZero provide rkentry.CertEntry.
func WithCertEntryZero(certEntry *rkentry.CertEntry) ZeroEntryOption {
	return func(entry *ZeroEntry) {
		entry.CertEntry = certEntry
	}
}

// WithSwEntryZero provide SwEntry.
func WithSwEntryZero(sw *SwEntry) ZeroEntryOption {
	return func(entry *ZeroEntry) {
		entry.SwEntry = sw
	}
}

// WithCommonServiceEntryZero provide CommonServiceEntry.
func WithCommonServiceEntryZero(commonServiceEntry *CommonServiceEntry) ZeroEntryOption {
	return func(entry *ZeroEntry) {
		entry.CommonServiceEntry = commonServiceEntry
	}
}

// WithInterceptorsZero provide user interceptors.
func WithInterceptorsZero(inters ...rest.Middleware) ZeroEntryOption {
	return func(entry *ZeroEntry) {
		if entry.Interceptors == nil {
			entry.Interceptors = make([]rest.Middleware, 0)
		}

		entry.Interceptors = append(entry.Interceptors, inters...)
	}
}

// WithPromEntryZero provide PromEntry.
func WithPromEntryZero(prom *PromEntry) ZeroEntryOption {
	return func(entry *ZeroEntry) {
		entry.PromEntry = prom
	}
}

// WithTVEntryZero provide TvEntry.
func WithTVEntryZero(tvEntry *TvEntry) ZeroEntryOption {
	return func(entry *ZeroEntry) {
		entry.TvEntry = tvEntry
	}
}

// WithRestConfZero provide *rest.RestConf.
func WithServerConfZero(conf *rest.RestConf) ZeroEntryOption {
	return func(entry *ZeroEntry) {
		entry.ServerConf = conf
	}
}

// WithServerRunOption provide *rest.RestConf.
func WithServerRunOption(opts ...rest.RunOption) ZeroEntryOption {
	return func(entry *ZeroEntry) {
		entry.ServerRunOption = append(entry.ServerRunOption, opts...)
	}
}

// GetZeroEntry Get ZeroEntry from rkentry.GlobalAppCtx.
func GetZeroEntry(name string) *ZeroEntry {
	entryRaw := rkentry.GlobalAppCtx.GetEntry(name)
	if entryRaw == nil {
		return nil
	}

	entry, _ := entryRaw.(*ZeroEntry)
	return entry
}

// RegisterZeroEntriesWithConfig register zero entries with provided config file (Must YAML file).
//
// Currently, support two ways to provide config file path.
// 1: With function parameters
// 2: With command line flag "--rkboot" described in rkcommon.BootConfigPathFlagKey (Will override function parameter if exists)
// Command line flag has high priority which would override function parameter
//
// Error handling:
// Process will shutdown if any errors occur with rkcommon.ShutdownWithError function
//
// Override elements in config file:
// We learned from HELM source code which would override elements in YAML file with "--set" flag followed with comma
// separated key/value pairs.
//
// We are using "--rkset" described in rkcommon.BootConfigOverrideKey in order to distinguish with user flags
// Example of common usage: ./binary_file --rkset "key1=val1,key2=val2"
// Example of nested map:   ./binary_file --rkset "outer.inner.key=val"
// Example of slice:        ./binary_file --rkset "outer[0].key=val"
func RegisterZeroEntriesWithConfig(configFilePath string) map[string]rkentry.Entry {
	res := make(map[string]rkentry.Entry)

	// 1: Decode config map into boot config struct
	config := &BootConfigZero{}
	rkcommon.UnmarshalBootConfig(configFilePath, config)

	// 2: Init zero entries with boot config
	for i := range config.Zero {
		element := config.Zero[i]
		if !element.Enabled {
			continue
		}

		name := element.Name

		zapLoggerEntry := rkentry.GlobalAppCtx.GetZapLoggerEntry(element.Logger.ZapLogger.Ref)
		if zapLoggerEntry == nil {
			zapLoggerEntry = rkentry.GlobalAppCtx.GetZapLoggerEntryDefault()
		}

		eventLoggerEntry := rkentry.GlobalAppCtx.GetEventLoggerEntry(element.Logger.EventLogger.Ref)
		if eventLoggerEntry == nil {
			eventLoggerEntry = rkentry.GlobalAppCtx.GetEventLoggerEntryDefault()
		}

		promRegistry := prometheus.NewRegistry()
		// Did we enabled swagger?
		var swEntry *SwEntry
		if element.SW.Enabled {
			// Init swagger custom headers from config
			headers := make(map[string]string, 0)
			for i := range element.SW.Headers {
				header := element.SW.Headers[i]
				tokens := strings.Split(header, ":")
				if len(tokens) == 2 {
					headers[tokens[0]] = tokens[1]
				}
			}

			swEntry = NewSwEntry(
				WithNameSw(fmt.Sprintf("%s-sw", element.Name)),
				WithZapLoggerEntrySw(zapLoggerEntry),
				WithEventLoggerEntrySw(eventLoggerEntry),
				WithEnableCommonServiceSw(element.CommonService.Enabled),
				WithPortSw(element.Port),
				WithPathSw(element.SW.Path),
				WithJsonPathSw(element.SW.JsonPath),
				WithHeadersSw(headers))
		}

		// Did we enabled prometheus?
		var promEntry *PromEntry
		if element.Prom.Enabled {
			var pusher *rkprom.PushGatewayPusher
			if element.Prom.Pusher.Enabled {
				certEntry := rkentry.GlobalAppCtx.GetCertEntry(element.Prom.Pusher.Cert.Ref)
				var certStore *rkentry.CertStore

				if certEntry != nil {
					certStore = certEntry.Store
				}

				pusher, _ = rkprom.NewPushGatewayPusher(
					rkprom.WithIntervalMSPusher(time.Duration(element.Prom.Pusher.IntervalMs)*time.Millisecond),
					rkprom.WithRemoteAddressPusher(element.Prom.Pusher.RemoteAddress),
					rkprom.WithJobNamePusher(element.Prom.Pusher.JobName),
					rkprom.WithBasicAuthPusher(element.Prom.Pusher.BasicAuth),
					rkprom.WithZapLoggerEntryPusher(zapLoggerEntry),
					rkprom.WithEventLoggerEntryPusher(eventLoggerEntry),
					rkprom.WithCertStorePusher(certStore))
			}

			promRegistry.Register(prometheus.NewGoCollector())
			promEntry = NewPromEntry(
				WithNameProm(fmt.Sprintf("%s-prom", element.Name)),
				WithPortProm(element.Port),
				WithPathProm(element.Prom.Path),
				WithZapLoggerEntryProm(zapLoggerEntry),
				WithPromRegistryProm(promRegistry),
				WithEventLoggerEntryProm(eventLoggerEntry),
				WithPusherProm(pusher))

			if promEntry.Pusher != nil {
				promEntry.Pusher.SetGatherer(promEntry.Gatherer)
			}
		}

		inters := make([]rest.Middleware, 0)

		// Did we enabled logging interceptor?
		if element.Interceptors.LoggingZap.Enabled {
			opts := []rkzerolog.Option{
				rkzerolog.WithEntryNameAndType(element.Name, ZeroEntryType),
				rkzerolog.WithEventLoggerEntry(eventLoggerEntry),
				rkzerolog.WithZapLoggerEntry(zapLoggerEntry),
			}

			if strings.ToLower(element.Interceptors.LoggingZap.ZapLoggerEncoding) == "json" {
				opts = append(opts, rkzerolog.WithZapLoggerEncoding(rkzerolog.ENCODING_JSON))
			}

			if strings.ToLower(element.Interceptors.LoggingZap.EventLoggerEncoding) == "json" {
				opts = append(opts, rkzerolog.WithEventLoggerEncoding(rkzerolog.ENCODING_JSON))
			}

			if len(element.Interceptors.LoggingZap.ZapLoggerOutputPaths) > 0 {
				opts = append(opts, rkzerolog.WithZapLoggerOutputPaths(element.Interceptors.LoggingZap.ZapLoggerOutputPaths...))
			}

			if len(element.Interceptors.LoggingZap.EventLoggerOutputPaths) > 0 {
				opts = append(opts, rkzerolog.WithEventLoggerOutputPaths(element.Interceptors.LoggingZap.EventLoggerOutputPaths...))
			}

			inters = append(inters, rkzerolog.Interceptor(opts...))
		}

		// Did we enabled metrics interceptor?
		if element.Interceptors.MetricsProm.Enabled {
			opts := []rkzerometrics.Option{
				rkzerometrics.WithRegisterer(promRegistry),
				rkzerometrics.WithEntryNameAndType(element.Name, ZeroEntryType),
			}

			inters = append(inters, rkzerometrics.Interceptor(opts...))
		}

		// Did we enabled tracing interceptor?
		if element.Interceptors.TracingTelemetry.Enabled {
			var exporter trace.SpanExporter

			if element.Interceptors.TracingTelemetry.Exporter.File.Enabled {
				exporter = rkzerotrace.CreateFileExporter(element.Interceptors.TracingTelemetry.Exporter.File.OutputPath)
			}

			if element.Interceptors.TracingTelemetry.Exporter.Jaeger.Agent.Enabled {
				opts := make([]jaeger.AgentEndpointOption, 0)
				if len(element.Interceptors.TracingTelemetry.Exporter.Jaeger.Agent.Host) > 0 {
					opts = append(opts,
						jaeger.WithAgentHost(element.Interceptors.TracingTelemetry.Exporter.Jaeger.Agent.Host))
				}
				if element.Interceptors.TracingTelemetry.Exporter.Jaeger.Agent.Port > 0 {
					opts = append(opts,
						jaeger.WithAgentPort(
							fmt.Sprintf("%d", element.Interceptors.TracingTelemetry.Exporter.Jaeger.Agent.Port)))
				}

				exporter = rkzerotrace.CreateJaegerExporter(jaeger.WithAgentEndpoint(opts...))
			}

			if element.Interceptors.TracingTelemetry.Exporter.Jaeger.Collector.Enabled {
				opts := []jaeger.CollectorEndpointOption{
					jaeger.WithUsername(element.Interceptors.TracingTelemetry.Exporter.Jaeger.Collector.Username),
					jaeger.WithPassword(element.Interceptors.TracingTelemetry.Exporter.Jaeger.Collector.Password),
				}

				if len(element.Interceptors.TracingTelemetry.Exporter.Jaeger.Collector.Endpoint) > 0 {
					opts = append(opts, jaeger.WithEndpoint(element.Interceptors.TracingTelemetry.Exporter.Jaeger.Collector.Endpoint))
				}

				exporter = rkzerotrace.CreateJaegerExporter(jaeger.WithCollectorEndpoint(opts...))
			}

			opts := []rkzerotrace.Option{
				rkzerotrace.WithEntryNameAndType(element.Name, ZeroEntryType),
				rkzerotrace.WithExporter(exporter),
			}

			inters = append(inters, rkzerotrace.Interceptor(opts...))
		}

		// Did we enabled jwt interceptor?
		if element.Interceptors.Jwt.Enabled {
			var signingKey []byte
			if len(element.Interceptors.Jwt.SigningKey) > 0 {
				signingKey = []byte(element.Interceptors.Jwt.SigningKey)
			}

			opts := []rkzerojwt.Option{
				rkzerojwt.WithEntryNameAndType(element.Name, ZeroEntryType),
				rkzerojwt.WithSigningKey(signingKey),
				rkzerojwt.WithSigningAlgorithm(element.Interceptors.Jwt.SigningAlgo),
				rkzerojwt.WithTokenLookup(element.Interceptors.Jwt.TokenLookup),
				rkzerojwt.WithAuthScheme(element.Interceptors.Jwt.AuthScheme),
				rkzerojwt.WithIgnorePrefix(element.Interceptors.Jwt.IgnorePrefix...),
			}

			for _, v := range element.Interceptors.Jwt.SigningKeys {
				tokens := strings.SplitN(v, ":", 2)
				if len(tokens) == 2 {
					opts = append(opts, rkzerojwt.WithSigningKeys(tokens[0], tokens[1]))
				}
			}

			inters = append(inters, rkzerojwt.Interceptor(opts...))
		}

		// Did we enabled secure interceptor?
		if element.Interceptors.Secure.Enabled {
			opts := []rkzerosec.Option{
				rkzerosec.WithEntryNameAndType(element.Name, ZeroEntryType),
				rkzerosec.WithXSSProtection(element.Interceptors.Secure.XssProtection),
				rkzerosec.WithContentTypeNosniff(element.Interceptors.Secure.ContentTypeNosniff),
				rkzerosec.WithXFrameOptions(element.Interceptors.Secure.XFrameOptions),
				rkzerosec.WithHSTSMaxAge(element.Interceptors.Secure.HstsMaxAge),
				rkzerosec.WithHSTSExcludeSubdomains(element.Interceptors.Secure.HstsExcludeSubdomains),
				rkzerosec.WithHSTSPreloadEnabled(element.Interceptors.Secure.HstsPreloadEnabled),
				rkzerosec.WithContentSecurityPolicy(element.Interceptors.Secure.ContentSecurityPolicy),
				rkzerosec.WithCSPReportOnly(element.Interceptors.Secure.CspReportOnly),
				rkzerosec.WithReferrerPolicy(element.Interceptors.Secure.ReferrerPolicy),
				rkzerosec.WithIgnorePrefix(element.Interceptors.Secure.IgnorePrefix...),
			}

			inters = append(inters, rkzerosec.Interceptor(opts...))
		}

		// Did we enabled csrf interceptor?
		if element.Interceptors.Csrf.Enabled {
			opts := []rkzerocsrf.Option{
				rkzerocsrf.WithEntryNameAndType(element.Name, ZeroEntryType),
				rkzerocsrf.WithTokenLength(element.Interceptors.Csrf.TokenLength),
				rkzerocsrf.WithTokenLookup(element.Interceptors.Csrf.TokenLookup),
				rkzerocsrf.WithCookieName(element.Interceptors.Csrf.CookieName),
				rkzerocsrf.WithCookieDomain(element.Interceptors.Csrf.CookieDomain),
				rkzerocsrf.WithCookiePath(element.Interceptors.Csrf.CookiePath),
				rkzerocsrf.WithCookieMaxAge(element.Interceptors.Csrf.CookieMaxAge),
				rkzerocsrf.WithCookieHTTPOnly(element.Interceptors.Csrf.CookieHttpOnly),
				rkzerocsrf.WithIgnorePrefix(element.Interceptors.Csrf.IgnorePrefix...),
			}

			// convert to string to cookie same sites
			sameSite := http.SameSiteDefaultMode

			switch strings.ToLower(element.Interceptors.Csrf.CookieSameSite) {
			case "lax":
				sameSite = http.SameSiteLaxMode
			case "strict":
				sameSite = http.SameSiteStrictMode
			case "none":
				sameSite = http.SameSiteNoneMode
			default:
				sameSite = http.SameSiteDefaultMode
			}

			opts = append(opts, rkzerocsrf.WithCookieSameSite(sameSite))

			inters = append(inters, rkzerocsrf.Interceptor(opts...))
		}

		// Did we enabled cors interceptor?
		if element.Interceptors.Cors.Enabled {
			opts := []rkzerocors.Option{
				rkzerocors.WithEntryNameAndType(element.Name, ZeroEntryType),
				rkzerocors.WithAllowOrigins(element.Interceptors.Cors.AllowOrigins...),
				rkzerocors.WithAllowCredentials(element.Interceptors.Cors.AllowCredentials),
				rkzerocors.WithExposeHeaders(element.Interceptors.Cors.ExposeHeaders...),
				rkzerocors.WithMaxAge(element.Interceptors.Cors.MaxAge),
				rkzerocors.WithAllowHeaders(element.Interceptors.Cors.AllowHeaders...),
				rkzerocors.WithAllowMethods(element.Interceptors.Cors.AllowMethods...),
			}

			inters = append(inters, rkzerocors.Interceptor(opts...))
		}

		// Did we enabled meta interceptor?
		if element.Interceptors.Meta.Enabled {
			opts := []rkzerometa.Option{
				rkzerometa.WithEntryNameAndType(element.Name, ZeroEntryType),
				rkzerometa.WithPrefix(element.Interceptors.Meta.Prefix),
			}

			inters = append(inters, rkzerometa.Interceptor(opts...))
		}

		// Did we enabled auth interceptor?
		if element.Interceptors.Auth.Enabled {
			opts := make([]rkzeroauth.Option, 0)
			opts = append(opts,
				rkzeroauth.WithEntryNameAndType(element.Name, ZeroEntryType),
				rkzeroauth.WithBasicAuth(element.Name, element.Interceptors.Auth.Basic...),
				rkzeroauth.WithApiKeyAuth(element.Interceptors.Auth.ApiKey...))

			// Add exceptional path
			if swEntry != nil {
				opts = append(opts, rkzeroauth.WithIgnorePrefix(strings.TrimSuffix(swEntry.Path, "/")))
			}

			opts = append(opts, rkzeroauth.WithIgnorePrefix("/rk/v1/assets"))
			opts = append(opts, rkzeroauth.WithIgnorePrefix(element.Interceptors.Auth.IgnorePrefix...))

			inters = append(inters, rkzeroauth.Interceptor(opts...))
		}

		// Did we enabled timeout interceptor?
		// This should be in front of rate limit interceptor since rate limit may block over the threshold of timeout.
		if element.Interceptors.Timeout.Enabled {
			opts := make([]rkzerotimeout.Option, 0)
			opts = append(opts,
				rkzerotimeout.WithEntryNameAndType(element.Name, ZeroEntryType))

			timeout := time.Duration(element.Interceptors.Timeout.TimeoutMs) * time.Millisecond
			opts = append(opts, rkzerotimeout.WithTimeoutAndResp(timeout, nil))

			for i := range element.Interceptors.Timeout.Paths {
				e := element.Interceptors.Timeout.Paths[i]
				timeout := time.Duration(e.TimeoutMs) * time.Millisecond
				opts = append(opts, rkzerotimeout.WithTimeoutAndRespByPath(e.Path, timeout, nil))
			}

			inters = append(inters, rkzerotimeout.Interceptor(opts...))
		}

		// Did we enabled rate limit interceptor?
		if element.Interceptors.RateLimit.Enabled {
			opts := make([]rkzerolimit.Option, 0)
			opts = append(opts,
				rkzerolimit.WithEntryNameAndType(element.Name, ZeroEntryType))

			if len(element.Interceptors.RateLimit.Algorithm) > 0 {
				opts = append(opts, rkzerolimit.WithAlgorithm(element.Interceptors.RateLimit.Algorithm))
			}
			opts = append(opts, rkzerolimit.WithReqPerSec(element.Interceptors.RateLimit.ReqPerSec))

			for i := range element.Interceptors.RateLimit.Paths {
				e := element.Interceptors.RateLimit.Paths[i]
				opts = append(opts, rkzerolimit.WithReqPerSecByPath(e.Path, e.ReqPerSec))
			}

			inters = append(inters, rkzerolimit.Interceptor(opts...))
		}

		// Did we enabled common service?
		var commonServiceEntry *CommonServiceEntry
		if element.CommonService.Enabled {
			commonServiceEntry = NewCommonServiceEntry(
				WithNameCommonService(fmt.Sprintf("%s-commonService", element.Name)),
				WithZapLoggerEntryCommonService(zapLoggerEntry),
				WithEventLoggerEntryCommonService(eventLoggerEntry))
		}

		// Did we enabled tv?
		var tvEntry *TvEntry
		if element.TV.Enabled {
			tvEntry = NewTvEntry(
				WithNameTv(fmt.Sprintf("%s-tv", element.Name)),
				WithZapLoggerEntryTv(zapLoggerEntry),
				WithEventLoggerEntryTv(eventLoggerEntry))
		}

		certEntry := rkentry.GlobalAppCtx.GetCertEntry(element.Cert.Ref)

		entry := RegisterZeroEntry(
			WithNameZero(name),
			WithDescriptionZero(element.Description),
			WithPortZero(element.Port),
			WithZapLoggerEntryZero(zapLoggerEntry),
			WithEventLoggerEntryZero(eventLoggerEntry),
			WithCertEntryZero(certEntry),
			WithPromEntryZero(promEntry),
			WithTVEntryZero(tvEntry),
			WithCommonServiceEntryZero(commonServiceEntry),
			WithSwEntryZero(swEntry),
			WithInterceptorsZero(inters...))

		res[name] = entry
	}

	return res
}

// RegisterZeroEntry register ZeroEntry with options.
func RegisterZeroEntry(opts ...ZeroEntryOption) *ZeroEntry {
	entry := &ZeroEntry{
		EntryType:        ZeroEntryType,
		EntryDescription: ZeroEntryDescription,
		Port:             8080,
		ServerRunOption:  make([]rest.RunOption, 0),
	}

	for i := range opts {
		opts[i](entry)
	}

	// insert panic interceptor
	entry.Interceptors = append(entry.Interceptors, rkzeropanic.Interceptor(
		rkzeropanic.WithEntryNameAndType(entry.EntryName, entry.EntryType)))

	if entry.ZapLoggerEntry == nil {
		entry.ZapLoggerEntry = rkentry.GlobalAppCtx.GetZapLoggerEntryDefault()
	}

	if entry.EventLoggerEntry == nil {
		entry.EventLoggerEntry = rkentry.GlobalAppCtx.GetEventLoggerEntryDefault()
	}

	if len(entry.EntryName) < 1 {
		entry.EntryName = "ZeroServer-" + strconv.FormatUint(entry.Port, 10)
	}

	if entry.Server == nil {
		if entry.ServerConf != nil {
			entry.Server = rest.MustNewServer(*entry.ServerConf, entry.ServerRunOption...)
		} else {
			serverConf := rest.RestConf{
				Host: "0.0.0.0",
				Port: int(entry.Port),
			}
			serverConf.Name = entry.EntryName
			// disable log
			serverConf.Log.Mode = "console"
			serverConf.Log.Level = "severe"
			serverConf.Telemetry.Sampler = 0
			entry.Server = rest.MustNewServer(serverConf, entry.ServerRunOption...)
		}
	}

	// Init TLS config
	if entry.IsTlsEnabled() {
		var cert tls.Certificate
		var err error
		if cert, err = tls.X509KeyPair(entry.CertEntry.Store.ServerCert, entry.CertEntry.Store.ServerKey); err != nil {
			entry.ZapLoggerEntry.GetLogger().Error("Error occurs while parsing TLS.", zap.String("cert", entry.CertEntry.String()))
		} else {
			entry.TlsConfig = &tls.Config{
				InsecureSkipVerify: true,
				Certificates:       []tls.Certificate{cert},
			}
		}

		rest.WithTLSConfig(entry.TlsConfig)(entry.Server)
	}

	rkentry.GlobalAppCtx.AddEntry(entry)

	return entry
}

// Bootstrap ZeroEntry.
func (entry *ZeroEntry) Bootstrap(ctx context.Context) {
	event, _ := entry.logBasicInfo("Bootstrap")

	// Is swagger enabled?
	if entry.IsSwEnabled() {
		// Register swagger path into Router.
		// for sw/
		entry.Server.AddRoute(rest.Route{
			Method:  http.MethodGet,
			Path:    path.Join(entry.SwEntry.Path),
			Handler: entry.SwEntry.ConfigFileHandler(),
		})
		// for sw/*
		entry.Server.AddRoute(rest.Route{
			Method:  http.MethodGet,
			Path:    path.Join(entry.SwEntry.Path, ":*"),
			Handler: entry.SwEntry.ConfigFileHandler(),
		})

		// for sw/css
		entry.Server.AddRoute(rest.Route{
			Method:  http.MethodGet,
			Path:    "/rk/v1/assets/sw/css/:*",
			Handler: entry.SwEntry.AssetsFileHandler(),
		})
		// for sw/css/3.35.1
		entry.Server.AddRoute(rest.Route{
			Method:  http.MethodGet,
			Path:    "/rk/v1/assets/sw/css/3.35.1/:*",
			Handler: entry.SwEntry.AssetsFileHandler(),
		})
		// for sw/js/3.35.1
		entry.Server.AddRoute(rest.Route{
			Method:  http.MethodGet,
			Path:    "/rk/v1/assets/sw/js/3.35.1/:*",
			Handler: entry.SwEntry.AssetsFileHandler(),
		})

		// Bootstrap swagger entry.
		entry.SwEntry.Bootstrap(ctx)
	}

	// Is prometheus enabled?
	if entry.IsPromEnabled() {
		// Register prom path into Router.
		entry.Server.AddRoute(rest.Route{
			Method: http.MethodGet,
			Path:   entry.PromEntry.Path,
			Handler: func(writer http.ResponseWriter, request *http.Request) {
				promhttp.HandlerFor(entry.PromEntry.Gatherer, promhttp.HandlerOpts{}).ServeHTTP(writer, request)
			},
		})

		// don't start with http handler, we will handle it by ourselves
		entry.PromEntry.Bootstrap(ctx)
	}

	// Is common service enabled?
	if entry.IsCommonServiceEnabled() {
		// Register common service path into Router.
		entry.Server.AddRoute(rest.Route{
			Method:  http.MethodGet,
			Path:    "/rk/v1/healthy",
			Handler: entry.CommonServiceEntry.Healthy,
		})
		entry.Server.AddRoute(rest.Route{
			Method:  http.MethodGet,
			Path:    "/rk/v1/gc",
			Handler: entry.CommonServiceEntry.Gc,
		})
		entry.Server.AddRoute(rest.Route{
			Method:  http.MethodGet,
			Path:    "/rk/v1/info",
			Handler: entry.CommonServiceEntry.Info,
		})
		entry.Server.AddRoute(rest.Route{
			Method:  http.MethodGet,
			Path:    "/rk/v1/configs",
			Handler: entry.CommonServiceEntry.Configs,
		})
		entry.Server.AddRoute(rest.Route{
			Method:  http.MethodGet,
			Path:    "/rk/v1/sys",
			Handler: entry.CommonServiceEntry.Sys,
		})
		entry.Server.AddRoute(rest.Route{
			Method:  http.MethodGet,
			Path:    "/rk/v1/entries",
			Handler: entry.CommonServiceEntry.Entries,
		})
		entry.Server.AddRoute(rest.Route{
			Method:  http.MethodGet,
			Path:    "/rk/v1/certs",
			Handler: entry.CommonServiceEntry.Certs,
		})
		entry.Server.AddRoute(rest.Route{
			Method:  http.MethodGet,
			Path:    "/rk/v1/logs",
			Handler: entry.CommonServiceEntry.Logs,
		})
		entry.Server.AddRoute(rest.Route{
			Method:  http.MethodGet,
			Path:    "/rk/v1/deps",
			Handler: entry.CommonServiceEntry.Deps,
		})
		entry.Server.AddRoute(rest.Route{
			Method:  http.MethodGet,
			Path:    "/rk/v1/license",
			Handler: entry.CommonServiceEntry.License,
		})
		entry.Server.AddRoute(rest.Route{
			Method:  http.MethodGet,
			Path:    "/rk/v1/readme",
			Handler: entry.CommonServiceEntry.Readme,
		})
		entry.Server.AddRoute(rest.Route{
			Method:  http.MethodGet,
			Path:    "/rk/v1/git",
			Handler: entry.CommonServiceEntry.Git,
		})

		// Bootstrap common service entry.
		entry.CommonServiceEntry.Bootstrap(ctx)
	}

	// Is TV enabled?
	if entry.IsTvEnabled() {
		// Bootstrap TV entry.
		entry.Server.AddRoute(rest.Route{
			Method: http.MethodGet,
			Path:   "/rk/v1/tv",
			Handler: func(writer http.ResponseWriter, request *http.Request) {
				writer.Header().Set("Location", "/rk/v1/tv/overview")
				writer.WriteHeader(http.StatusTemporaryRedirect)
			},
		})
		// for index
		entry.Server.AddRoute(rest.Route{
			Method:  http.MethodGet,
			Path:    "/rk/v1/tv/:*",
			Handler: entry.TvEntry.TV,
		})

		// for css/fonts
		entry.Server.AddRoute(rest.Route{
			Method:  http.MethodGet,
			Path:    "/rk/v1/assets/tv/css/fonts/:*",
			Handler: entry.TvEntry.AssetsFileHandler(),
		})
		// for css
		entry.Server.AddRoute(rest.Route{
			Method:  http.MethodGet,
			Path:    "/rk/v1/assets/tv/css/:*",
			Handler: entry.TvEntry.AssetsFileHandler(),
		})
		// for image
		entry.Server.AddRoute(rest.Route{
			Method:  http.MethodGet,
			Path:    "/rk/v1/assets/tv/image/:*",
			Handler: entry.TvEntry.AssetsFileHandler(),
		})
		// for js
		entry.Server.AddRoute(rest.Route{
			Method:  http.MethodGet,
			Path:    "/rk/v1/assets/tv/js/:*",
			Handler: entry.TvEntry.AssetsFileHandler(),
		})
		// for webfonts
		entry.Server.AddRoute(rest.Route{
			Method:  http.MethodGet,
			Path:    "/rk/v1/assets/tv/webfonts/:*",
			Handler: entry.TvEntry.AssetsFileHandler(),
		})

		entry.TvEntry.Bootstrap(ctx)
	}

	// Default interceptor should be at front
	for _, v := range entry.Interceptors {
		entry.Server.Use(v)
	}

	go func(zeroEntry *ZeroEntry) {
		if entry.Server != nil {
			entry.Server.Start()
		}
	}(entry)

	entry.EventLoggerEntry.GetEventHelper().Finish(event)
}

// Interrupt ZeroEntry.
func (entry *ZeroEntry) Interrupt(ctx context.Context) {
	event, _ := entry.logBasicInfo("Interrupt")

	if entry.IsSwEnabled() {
		// Interrupt swagger entry
		entry.SwEntry.Interrupt(ctx)
	}

	if entry.IsPromEnabled() {
		// Interrupt prometheus entry
		entry.PromEntry.Interrupt(ctx)
	}

	if entry.IsCommonServiceEnabled() {
		// Interrupt common service entry
		entry.CommonServiceEntry.Interrupt(ctx)
	}

	if entry.IsTvEnabled() {
		// Interrupt common service entry
		entry.TvEntry.Interrupt(ctx)
	}

	if entry.Server != nil {
		entry.Server.Stop()
	}

	entry.EventLoggerEntry.GetEventHelper().Finish(event)
}

// GetName Get entry name.
func (entry *ZeroEntry) GetName() string {
	return entry.EntryName
}

// GetType Get entry type.
func (entry *ZeroEntry) GetType() string {
	return entry.EntryType
}

// GetDescription Get description of entry.
func (entry *ZeroEntry) GetDescription() string {
	return entry.EntryDescription
}

// String Stringfy entry.
func (entry *ZeroEntry) String() string {
	bytes, _ := json.Marshal(entry)
	return string(bytes)
}

// MarshalJSON Marshal entry.
func (entry *ZeroEntry) MarshalJSON() ([]byte, error) {
	m := map[string]interface{}{
		"entryName":          entry.EntryName,
		"entryType":          entry.EntryType,
		"entryDescription":   entry.EntryDescription,
		"eventLoggerEntry":   entry.EventLoggerEntry.GetName(),
		"zapLoggerEntry":     entry.ZapLoggerEntry.GetName(),
		"port":               entry.Port,
		"swEntry":            entry.SwEntry,
		"commonServiceEntry": entry.CommonServiceEntry,
		"promEntry":          entry.PromEntry,
		"tvEntry":            entry.TvEntry,
	}

	if entry.CertEntry != nil {
		m["certEntry"] = entry.CertEntry.GetName()
	}

	interceptorsStr := make([]string, 0)
	m["interceptors"] = &interceptorsStr

	for i := range entry.Interceptors {
		element := entry.Interceptors[i]
		interceptorsStr = append(interceptorsStr,
			path.Base(runtime.FuncForPC(reflect.ValueOf(element).Pointer()).Name()))
	}

	return json.Marshal(&m)
}

// UnmarshalJSON Not supported.
func (entry *ZeroEntry) UnmarshalJSON([]byte) error {
	return nil
}

// AddInterceptor Add interceptors.
// This function should be called before Bootstrap() called.
func (entry *ZeroEntry) AddInterceptor(inters ...rest.Middleware) {
	entry.Interceptors = append(entry.Interceptors, inters...)
}

// IsTlsEnabled Is TLS enabled?
func (entry *ZeroEntry) IsTlsEnabled() bool {
	return entry.CertEntry != nil && entry.CertEntry.Store != nil
}

// IsSwEnabled Is swagger entry enabled?
func (entry *ZeroEntry) IsSwEnabled() bool {
	return entry.SwEntry != nil
}

// IsCommonServiceEnabled Is common service entry enabled?
func (entry *ZeroEntry) IsCommonServiceEnabled() bool {
	return entry.CommonServiceEntry != nil
}

// IsTvEnabled Is TV entry enabled?
func (entry *ZeroEntry) IsTvEnabled() bool {
	return entry.TvEntry != nil
}

// IsPromEnabled Is prometheus entry enabled?
func (entry *ZeroEntry) IsPromEnabled() bool {
	return entry.PromEntry != nil
}

// Add basic fields into event.
func (entry *ZeroEntry) logBasicInfo(operation string) (rkquery.Event, *zap.Logger) {
	event := entry.EventLoggerEntry.GetEventHelper().Start(
		operation,
		rkquery.WithEntryName(entry.GetName()),
		rkquery.WithEntryType(entry.GetType()))
	logger := entry.ZapLoggerEntry.GetLogger().With(
		zap.String("eventId", event.GetEventId()),
		zap.String("entryName", entry.EntryName))

	// add general info
	event.AddPayloads(
		zap.Uint64("zeroPort", entry.Port))

	// add SwEntry info
	if entry.IsSwEnabled() {
		event.AddPayloads(
			zap.Bool("swEnabled", true),
			zap.String("swPath", entry.SwEntry.Path))
	}

	// add CommonServiceEntry info
	if entry.IsCommonServiceEnabled() {
		event.AddPayloads(
			zap.Bool("commonServiceEnabled", true),
			zap.String("commonServicePathPrefix", "/rk/v1/"))
	}

	// add TvEntry info
	if entry.IsTvEnabled() {
		event.AddPayloads(
			zap.Bool("tvEnabled", true),
			zap.String("tvPath", "/rk/v1/tv/"))
	}

	// add PromEntry info
	if entry.IsPromEnabled() {
		event.AddPayloads(
			zap.Bool("promEnabled", true),
			zap.Uint64("promPort", entry.PromEntry.Port),
			zap.String("promPath", entry.PromEntry.Path))
	}

	// add tls info
	if entry.IsTlsEnabled() {
		event.AddPayloads(
			zap.Bool("tlsEnabled", true))
	}

	logger.Info(fmt.Sprintf("%s zeroEntry", operation))

	return event, logger

}
