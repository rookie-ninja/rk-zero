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
	"github.com/rookie-ninja/rk-entry/middleware/auth"
	"github.com/rookie-ninja/rk-entry/middleware/cors"
	"github.com/rookie-ninja/rk-entry/middleware/csrf"
	"github.com/rookie-ninja/rk-entry/middleware/jwt"
	"github.com/rookie-ninja/rk-entry/middleware/log"
	"github.com/rookie-ninja/rk-entry/middleware/meta"
	"github.com/rookie-ninja/rk-entry/middleware/metrics"
	"github.com/rookie-ninja/rk-entry/middleware/panic"
	"github.com/rookie-ninja/rk-entry/middleware/ratelimit"
	"github.com/rookie-ninja/rk-entry/middleware/secure"
	"github.com/rookie-ninja/rk-entry/middleware/tracing"
	"github.com/rookie-ninja/rk-query"
	"github.com/rookie-ninja/rk-zero/interceptor/auth"
	"github.com/rookie-ninja/rk-zero/interceptor/context"
	"github.com/rookie-ninja/rk-zero/interceptor/cors"
	"github.com/rookie-ninja/rk-zero/interceptor/csrf"
	"github.com/rookie-ninja/rk-zero/interceptor/jwt"
	"github.com/rookie-ninja/rk-zero/interceptor/log/zap"
	"github.com/rookie-ninja/rk-zero/interceptor/meta"
	"github.com/rookie-ninja/rk-zero/interceptor/metrics/prom"
	"github.com/rookie-ninja/rk-zero/interceptor/panic"
	"github.com/rookie-ninja/rk-zero/interceptor/ratelimit"
	"github.com/rookie-ninja/rk-zero/interceptor/secure"
	"github.com/rookie-ninja/rk-zero/interceptor/tracing/telemetry"
	"github.com/tal-tech/go-zero/rest"
	"github.com/tal-tech/go-zero/rest/pathvar"
	"go.uber.org/zap"
	"net/http"
	"path"
	"reflect"
	"runtime"
	"strconv"
	"strings"
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

// BootConfig boot config which is for zero entry.
type BootConfig struct {
	Zero []struct {
		Enabled     bool   `yaml:"enabled" json:"enabled"`
		Name        string `yaml:"name" json:"name"`
		Port        uint64 `yaml:"port" json:"port"`
		Description string `yaml:"description" json:"description"`
		Cert        struct {
			Ref string `yaml:"ref" json:"ref"`
		} `yaml:"cert" json:"cert"`
		SW            rkentry.BootConfigSw            `yaml:"sw" json:"sw"`
		CommonService rkentry.BootConfigCommonService `yaml:"commonService" json:"commonService"`
		TV            rkentry.BootConfigTv            `yaml:"tv" json:"tv"`
		Prom          rkentry.BootConfigProm          `yaml:"prom" json:"prom"`
		Interceptors  struct {
			LoggingZap       rkmidlog.BootConfig     `yaml:"loggingZap" json:"loggingZap"`
			MetricsProm      rkmidmetrics.BootConfig `yaml:"metricsProm" json:"metricsProm"`
			Auth             rkmidauth.BootConfig    `yaml:"auth" json:"auth"`
			Cors             rkmidcors.BootConfig    `yaml:"cors" json:"cors"`
			Meta             rkmidmeta.BootConfig    `yaml:"meta" json:"meta"`
			Jwt              rkmidjwt.BootConfig     `yaml:"jwt" json:"jwt"`
			Secure           rkmidsec.BootConfig     `yaml:"secure" json:"secure"`
			RateLimit        rkmidlimit.BootConfig   `yaml:"rateLimit" json:"rateLimit"`
			Csrf             rkmidcsrf.BootConfig    `yaml:"csrf" yaml:"csrf"`
			TracingTelemetry rkmidtrace.BootConfig   `yaml:"tracingTelemetry" json:"tracingTelemetry"`
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
	EntryName          string                      `json:"entryName" yaml:"entryName"`
	EntryType          string                      `json:"entryType" yaml:"entryType"`
	EntryDescription   string                      `json:"-" yaml:"-"`
	ZapLoggerEntry     *rkentry.ZapLoggerEntry     `json:"-" yaml:"-"`
	EventLoggerEntry   *rkentry.EventLoggerEntry   `json:"-" yaml:"-"`
	Port               uint64                      `json:"port" yaml:"port"`
	CertEntry          *rkentry.CertEntry          `json:"-" yaml:"-"`
	SwEntry            *rkentry.SwEntry            `json:"-" yaml:"-"`
	CommonServiceEntry *rkentry.CommonServiceEntry `json:"-" yaml:"-"`
	Server             *rest.Server                `json:"-" yaml:"-"`
	ServerConf         *rest.RestConf              `json:"-" yaml:"-"`
	ServerRunOption    []rest.RunOption            `json:"-" yaml:"-"`
	TlsConfig          *tls.Config                 `json:"-" yaml:"-"`
	Interceptors       []rest.Middleware           `json:"-" yaml:"-"`
	PromEntry          *rkentry.PromEntry          `json:"-" yaml:"-"`
	TvEntry            *rkentry.TvEntry            `json:"-" yaml:"-"`
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
	config := &BootConfig{}
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

		// Register swagger entry
		swEntry := rkentry.RegisterSwEntryWithConfig(&element.SW, element.Name, element.Port,
			zapLoggerEntry, eventLoggerEntry, element.CommonService.Enabled)

		// Register prometheus entry
		promRegistry := prometheus.NewRegistry()
		promEntry := rkentry.RegisterPromEntryWithConfig(&element.Prom, element.Name, element.Port,
			zapLoggerEntry, eventLoggerEntry, promRegistry)

		// Register common service entry
		commonServiceEntry := rkentry.RegisterCommonServiceEntryWithConfig(&element.CommonService, element.Name,
			zapLoggerEntry, eventLoggerEntry)

		// Register TV entry
		tvEntry := rkentry.RegisterTvEntryWithConfig(&element.TV, element.Name,
			zapLoggerEntry, eventLoggerEntry)

		inters := make([]rest.Middleware, 0)

		// logging middlewares
		if element.Interceptors.LoggingZap.Enabled {
			inters = append(inters, rkzerolog.Interceptor(
				rkmidlog.ToOptions(&element.Interceptors.LoggingZap, element.Name, ZeroEntryType,
					zapLoggerEntry, eventLoggerEntry)...))
		}

		// metrics middleware
		if element.Interceptors.MetricsProm.Enabled {
			inters = append(inters, rkzerometrics.Interceptor(
				rkmidmetrics.ToOptions(&element.Interceptors.MetricsProm, element.Name, ZeroEntryType,
					promRegistry, rkmidmetrics.LabelerTypeHttp)...))
		}

		// tracing middleware
		if element.Interceptors.TracingTelemetry.Enabled {
			inters = append(inters, rkzerotrace.Interceptor(
				rkmidtrace.ToOptions(&element.Interceptors.TracingTelemetry, element.Name, ZeroEntryType)...))
		}

		// jwt middleware
		if element.Interceptors.Jwt.Enabled {
			inters = append(inters, rkzerojwt.Interceptor(
				rkmidjwt.ToOptions(&element.Interceptors.Jwt, element.Name, ZeroEntryType)...))
		}

		// secure middleware
		if element.Interceptors.Secure.Enabled {
			inters = append(inters, rkzerosec.Interceptor(
				rkmidsec.ToOptions(&element.Interceptors.Secure, element.Name, ZeroEntryType)...))
		}

		// csrf middleware
		if element.Interceptors.Csrf.Enabled {
			inters = append(inters, rkzerocsrf.Interceptor(
				rkmidcsrf.ToOptions(&element.Interceptors.Csrf, element.Name, ZeroEntryType)...))
		}

		// cors middleware
		if element.Interceptors.Cors.Enabled {
			inters = append(inters, rkzerocors.Interceptor(
				rkmidcors.ToOptions(&element.Interceptors.Cors, element.Name, ZeroEntryType)...))
		}

		// meta middleware
		if element.Interceptors.Meta.Enabled {
			inters = append(inters, rkzerometa.Interceptor(
				rkmidmeta.ToOptions(&element.Interceptors.Meta, element.Name, ZeroEntryType)...))
		}

		// auth middlewares
		if element.Interceptors.Auth.Enabled {
			inters = append(inters, rkzeroauth.Interceptor(
				rkmidauth.ToOptions(&element.Interceptors.Auth, element.Name, ZeroEntryType)...))
		}

		// rate limit middleware
		if element.Interceptors.RateLimit.Enabled {
			inters = append(inters, rkzerolimit.Interceptor(
				rkmidlimit.ToOptions(&element.Interceptors.RateLimit, element.Name, ZeroEntryType)...))
		}

		certEntry := rkentry.GlobalAppCtx.GetCertEntry(element.Cert.Ref)

		entry := RegisterZeroEntry(
			WithName(name),
			WithDescription(element.Description),
			WithPort(element.Port),
			WithZapLoggerEntry(zapLoggerEntry),
			WithEventLoggerEntry(eventLoggerEntry),
			WithCertEntry(certEntry),
			WithPromEntry(promEntry),
			WithTvEntry(tvEntry),
			WithCommonServiceEntry(commonServiceEntry),
			WithSwEntry(swEntry))

		entry.AddInterceptor(inters...)

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

	entry.Server.Use(rkzeropanic.Interceptor(
		rkmidpanic.WithEntryNameAndType(entry.EntryName, entry.EntryType)))

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
			Path:    path.Join(entry.SwEntry.AssetsFilePath, "/css/:*"),
			Handler: entry.SwEntry.AssetsFileHandler(),
		})
		// for sw/css/3.35.1
		entry.Server.AddRoute(rest.Route{
			Method:  http.MethodGet,
			Path:    path.Join(entry.SwEntry.AssetsFilePath, "css/3.35.1/:*"),
			Handler: entry.SwEntry.AssetsFileHandler(),
		})
		// for sw/js/3.35.1
		entry.Server.AddRoute(rest.Route{
			Method:  http.MethodGet,
			Path:    path.Join(entry.SwEntry.AssetsFilePath, "js/3.35.1/:*"),
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
			Path:    entry.CommonServiceEntry.HealthyPath,
			Handler: entry.CommonServiceEntry.Healthy,
		})
		entry.Server.AddRoute(rest.Route{
			Method:  http.MethodGet,
			Path:    entry.CommonServiceEntry.GcPath,
			Handler: entry.CommonServiceEntry.Gc,
		})
		entry.Server.AddRoute(rest.Route{
			Method:  http.MethodGet,
			Path:    entry.CommonServiceEntry.InfoPath,
			Handler: entry.CommonServiceEntry.Info,
		})
		entry.Server.AddRoute(rest.Route{
			Method:  http.MethodGet,
			Path:    entry.CommonServiceEntry.ConfigsPath,
			Handler: entry.CommonServiceEntry.Configs,
		})
		entry.Server.AddRoute(rest.Route{
			Method:  http.MethodGet,
			Path:    entry.CommonServiceEntry.SysPath,
			Handler: entry.CommonServiceEntry.Sys,
		})
		entry.Server.AddRoute(rest.Route{
			Method:  http.MethodGet,
			Path:    entry.CommonServiceEntry.EntriesPath,
			Handler: entry.CommonServiceEntry.Entries,
		})
		entry.Server.AddRoute(rest.Route{
			Method:  http.MethodGet,
			Path:    entry.CommonServiceEntry.CertsPath,
			Handler: entry.CommonServiceEntry.Certs,
		})
		entry.Server.AddRoute(rest.Route{
			Method:  http.MethodGet,
			Path:    entry.CommonServiceEntry.LogsPath,
			Handler: entry.CommonServiceEntry.Logs,
		})
		entry.Server.AddRoute(rest.Route{
			Method:  http.MethodGet,
			Path:    entry.CommonServiceEntry.DepsPath,
			Handler: entry.CommonServiceEntry.Deps,
		})
		entry.Server.AddRoute(rest.Route{
			Method:  http.MethodGet,
			Path:    entry.CommonServiceEntry.LicensePath,
			Handler: entry.CommonServiceEntry.License,
		})
		entry.Server.AddRoute(rest.Route{
			Method:  http.MethodGet,
			Path:    entry.CommonServiceEntry.ReadmePath,
			Handler: entry.CommonServiceEntry.Readme,
		})
		entry.Server.AddRoute(rest.Route{
			Method:  http.MethodGet,
			Path:    entry.CommonServiceEntry.GitPath,
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
			Path:   strings.TrimSuffix(entry.TvEntry.BasePath, "/"),
			Handler: func(writer http.ResponseWriter, request *http.Request) {
				writer.Header().Set("Location", "/rk/v1/tv/overview")
				writer.WriteHeader(http.StatusTemporaryRedirect)
			},
		})
		// for index
		entry.Server.AddRoute(rest.Route{
			Method:  http.MethodGet,
			Path:    path.Join(entry.TvEntry.BasePath, ":*"),
			Handler: http.HandlerFunc(entry.TV),
		})

		// for css/fonts
		entry.Server.AddRoute(rest.Route{
			Method:  http.MethodGet,
			Path:    path.Join(entry.TvEntry.AssetsFilePath, "css/fonts/:*"),
			Handler: entry.TvEntry.AssetsFileHandler(),
		})
		// for css
		entry.Server.AddRoute(rest.Route{
			Method:  http.MethodGet,
			Path:    path.Join(entry.TvEntry.AssetsFilePath, "css/:*"),
			Handler: entry.TvEntry.AssetsFileHandler(),
		})
		// for image
		entry.Server.AddRoute(rest.Route{
			Method:  http.MethodGet,
			Path:    path.Join(entry.TvEntry.AssetsFilePath, "image/:*"),
			Handler: entry.TvEntry.AssetsFileHandler(),
		})
		// for js
		entry.Server.AddRoute(rest.Route{
			Method:  http.MethodGet,
			Path:    path.Join(entry.TvEntry.AssetsFilePath, "js/:*"),
			Handler: entry.TvEntry.AssetsFileHandler(),
		})
		// for webfonts
		entry.Server.AddRoute(rest.Route{
			Method:  http.MethodGet,
			Path:    path.Join(entry.TvEntry.AssetsFilePath, "webfonts/:*"),
			Handler: entry.TvEntry.AssetsFileHandler(),
		})

		entry.TvEntry.Bootstrap(ctx)
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

// ***************** Stringfy *****************

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

// ***************** Public functions *****************

// GetZeroEntry Get ZeroEntry from rkentry.GlobalAppCtx.
func GetZeroEntry(name string) *ZeroEntry {
	entryRaw := rkentry.GlobalAppCtx.GetEntry(name)
	if entryRaw == nil {
		return nil
	}

	entry, _ := entryRaw.(*ZeroEntry)
	return entry
}

// AddInterceptor Add interceptors.
// This function should be called before Bootstrap() called.
func (entry *ZeroEntry) AddInterceptor(inters ...rest.Middleware) {
	for i := range inters {
		entry.Server.Use(inters[i])

	}
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

// ***************** Helper function *****************

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

// ***************** Common Service Extension API *****************

// TV handler
func (entry *ZeroEntry) TV(w http.ResponseWriter, req *http.Request) {
	logger := rkzeroctx.GetLogger(req, w)

	param := pathvar.Vars(req)

	w.Header().Set("Content-Type", "text/html;charset=UTF-8")

	switch item := param["*"]; item {
	default:
		buf := entry.TvEntry.Action(item, logger)
		w.WriteHeader(http.StatusOK)
		w.Write(buf.Bytes())
	}
}

// ***************** Options *****************

// ZeroEntryOption zero entry option.
type ZeroEntryOption func(*ZeroEntry)

// WithName provide name.
func WithName(name string) ZeroEntryOption {
	return func(entry *ZeroEntry) {
		entry.EntryName = name
	}
}

// WithDescription provide name.
func WithDescription(description string) ZeroEntryOption {
	return func(entry *ZeroEntry) {
		entry.EntryDescription = description
	}
}

// WithPort provide port.
func WithPort(port uint64) ZeroEntryOption {
	return func(entry *ZeroEntry) {
		entry.Port = port
	}
}

// WithZapLoggerEntry provide rkentry.ZapLoggerEntry.
func WithZapLoggerEntry(zapLogger *rkentry.ZapLoggerEntry) ZeroEntryOption {
	return func(entry *ZeroEntry) {
		entry.ZapLoggerEntry = zapLogger
	}
}

// WithEventLoggerEntry provide rkentry.EventLoggerEntry.
func WithEventLoggerEntry(eventLogger *rkentry.EventLoggerEntry) ZeroEntryOption {
	return func(entry *ZeroEntry) {
		entry.EventLoggerEntry = eventLogger
	}
}

// WithCertEntry provide rkentry.CertEntry.
func WithCertEntry(certEntry *rkentry.CertEntry) ZeroEntryOption {
	return func(entry *ZeroEntry) {
		entry.CertEntry = certEntry
	}
}

// WithSwEntry provide SwEntry.
func WithSwEntry(sw *rkentry.SwEntry) ZeroEntryOption {
	return func(entry *ZeroEntry) {
		entry.SwEntry = sw
	}
}

// WithCommonServiceEntry provide CommonServiceEntry.
func WithCommonServiceEntry(commonServiceEntry *rkentry.CommonServiceEntry) ZeroEntryOption {
	return func(entry *ZeroEntry) {
		entry.CommonServiceEntry = commonServiceEntry
	}
}

// WithInterceptors provide user interceptors.
func WithInterceptors(inters ...rest.Middleware) ZeroEntryOption {
	return func(entry *ZeroEntry) {
		if entry.Interceptors == nil {
			entry.Interceptors = make([]rest.Middleware, 0)
		}

		entry.Interceptors = append(entry.Interceptors, inters...)
	}
}

// WithPromEntry provide PromEntry.
func WithPromEntry(prom *rkentry.PromEntry) ZeroEntryOption {
	return func(entry *ZeroEntry) {
		entry.PromEntry = prom
	}
}

// WithTvEntry provide TvEntry.
func WithTvEntry(tvEntry *rkentry.TvEntry) ZeroEntryOption {
	return func(entry *ZeroEntry) {
		entry.TvEntry = tvEntry
	}
}

// WithRestConf provide *rest.RestConf.
func WithServerConf(conf *rest.RestConf) ZeroEntryOption {
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
