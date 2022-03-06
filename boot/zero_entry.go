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
	"github.com/rookie-ninja/rk-entry/v2/entry"
	"github.com/rookie-ninja/rk-entry/v2/middleware"
	"github.com/rookie-ninja/rk-entry/v2/middleware/auth"
	"github.com/rookie-ninja/rk-entry/v2/middleware/cors"
	"github.com/rookie-ninja/rk-entry/v2/middleware/csrf"
	"github.com/rookie-ninja/rk-entry/v2/middleware/jwt"
	"github.com/rookie-ninja/rk-entry/v2/middleware/log"
	"github.com/rookie-ninja/rk-entry/v2/middleware/meta"
	"github.com/rookie-ninja/rk-entry/v2/middleware/panic"
	"github.com/rookie-ninja/rk-entry/v2/middleware/prom"
	"github.com/rookie-ninja/rk-entry/v2/middleware/ratelimit"
	"github.com/rookie-ninja/rk-entry/v2/middleware/secure"
	"github.com/rookie-ninja/rk-entry/v2/middleware/tracing"
	"github.com/rookie-ninja/rk-query"
	"github.com/rookie-ninja/rk-zero/middleware/auth"
	"github.com/rookie-ninja/rk-zero/middleware/cors"
	"github.com/rookie-ninja/rk-zero/middleware/csrf"
	"github.com/rookie-ninja/rk-zero/middleware/jwt"
	"github.com/rookie-ninja/rk-zero/middleware/log"
	"github.com/rookie-ninja/rk-zero/middleware/meta"
	"github.com/rookie-ninja/rk-zero/middleware/panic"
	"github.com/rookie-ninja/rk-zero/middleware/prom"
	"github.com/rookie-ninja/rk-zero/middleware/ratelimit"
	"github.com/rookie-ninja/rk-zero/middleware/secure"
	"github.com/rookie-ninja/rk-zero/middleware/tracing"
	"github.com/zeromicro/go-zero/rest"
	"go.uber.org/zap"
	"net/http"
	"path"
	"strconv"
	"strings"
	"sync"
)

const (
	// ZeroEntryType type of entry
	ZeroEntryType = "ZeroEntry"
)

// This must be declared in order to register registration function into rk context
// otherwise, rk-boot won't able to bootstrap zero entry automatically from boot config file
func init() {
	rkentry.RegisterEntryRegFunc(RegisterZeroEntryYAML)
}

// BootZero boot config which is for zero entry.
type BootZero struct {
	Zero []struct {
		Enabled       bool                          `yaml:"enabled" json:"enabled"`
		Name          string                        `yaml:"name" json:"name"`
		Port          uint64                        `yaml:"port" json:"port"`
		Description   string                        `yaml:"description" json:"description"`
		CertEntry     string                        `yaml:"certEntry" json:"certEntry"`
		LoggerEntry   string                        `yaml:"loggerEntry" json:"loggerEntry"`
		EventEntry    string                        `yaml:"eventEntry" json:"eventEntry"`
		SW            rkentry.BootSW                `yaml:"sw" json:"sw"`
		Docs          rkentry.BootDocs              `yaml:"docs" json:"docs"`
		CommonService rkentry.BootCommonService     `yaml:"commonService" json:"commonService"`
		Prom          rkentry.BootProm              `yaml:"prom" json:"prom"`
		Static        rkentry.BootStaticFileHandler `yaml:"static" json:"static"`
		Middleware    struct {
			Ignore    []string              `yaml:"ignore" json:"ignore"`
			Logging   rkmidlog.BootConfig   `yaml:"logging" json:"logging"`
			Prom      rkmidprom.BootConfig  `yaml:"prom" json:"prom"`
			Auth      rkmidauth.BootConfig  `yaml:"auth" json:"auth"`
			Cors      rkmidcors.BootConfig  `yaml:"cors" json:"cors"`
			Meta      rkmidmeta.BootConfig  `yaml:"meta" json:"meta"`
			Jwt       rkmidjwt.BootConfig   `yaml:"jwt" json:"jwt"`
			Secure    rkmidsec.BootConfig   `yaml:"secure" json:"secure"`
			RateLimit rkmidlimit.BootConfig `yaml:"rateLimit" json:"rateLimit"`
			Csrf      rkmidcsrf.BootConfig  `yaml:"csrf" yaml:"csrf"`
			Trace     rkmidtrace.BootConfig `yaml:"trace" json:"trace"`
		} `yaml:"middleware" json:"middleware"`
	} `yaml:"zero" json:"zero"`
}

// ZeroEntry implements rkentry.Entry interface.
type ZeroEntry struct {
	entryName          string                          `json:"-" yaml:"-"`
	entryType          string                          `json:"-" yaml:"-"`
	entryDescription   string                          `json:"-" yaml:"-"`
	LoggerEntry        *rkentry.LoggerEntry            `json:"-" yaml:"-"`
	EventEntry         *rkentry.EventEntry             `json:"-" yaml:"-"`
	Port               uint64                          `json:"port" yaml:"port"`
	CertEntry          *rkentry.CertEntry              `json:"-" yaml:"-"`
	SwEntry            *rkentry.SWEntry                `json:"-" yaml:"-"`
	DocsEntry          *rkentry.DocsEntry              `json:"-" yaml:"-"`
	CommonServiceEntry *rkentry.CommonServiceEntry     `json:"-" yaml:"-"`
	PromEntry          *rkentry.PromEntry              `json:"-" yaml:"-"`
	StaticFileEntry    *rkentry.StaticFileHandlerEntry `json:"-" yaml:"-"`
	Server             *rest.Server                    `json:"-" yaml:"-"`
	ServerConf         *rest.RestConf                  `json:"-" yaml:"-"`
	ServerRunOption    []rest.RunOption                `json:"-" yaml:"-"`
	TlsConfig          *tls.Config                     `json:"-" yaml:"-"`
	Middlewares        []rest.Middleware               `json:"-" yaml:"-"`
	bootstrapLogOnce   sync.Once                       `json:"-" yaml:"-"`
}

// RegisterZeroEntryYAML register zero entries with provided config file (Must YAML file).
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
func RegisterZeroEntryYAML(raw []byte) map[string]rkentry.Entry {
	res := make(map[string]rkentry.Entry)

	// 1: Decode config map into boot config struct
	config := &BootZero{}
	rkentry.UnmarshalBootYAML(raw, config)

	// 2: Init zero entries with boot config
	for i := range config.Zero {
		element := config.Zero[i]
		if !element.Enabled {
			continue
		}

		name := element.Name

		// logger entry
		loggerEntry := rkentry.GlobalAppCtx.GetLoggerEntry(element.LoggerEntry)
		if loggerEntry == nil {
			loggerEntry = rkentry.LoggerEntryStdout
		}

		// event entry
		eventEntry := rkentry.GlobalAppCtx.GetEventEntry(element.EventEntry)
		if eventEntry == nil {
			eventEntry = rkentry.EventEntryStdout
		}

		// cert entry
		certEntry := rkentry.GlobalAppCtx.GetCertEntry(element.CertEntry)

		// Register swagger entry
		swEntry := rkentry.RegisterSWEntry(&element.SW, rkentry.WithNameSWEntry(element.Name))

		// Register docs entry
		docsEntry := rkentry.RegisterDocsEntry(&element.Docs, rkentry.WithNameDocsEntry(element.Name))

		// Register prometheus entry
		promRegistry := prometheus.NewRegistry()
		promEntry := rkentry.RegisterPromEntry(&element.Prom, rkentry.WithRegistryPromEntry(promRegistry))

		// Register common service entry
		commonServiceEntry := rkentry.RegisterCommonServiceEntry(&element.CommonService)

		// Register static file handler
		staticEntry := rkentry.RegisterStaticFileHandlerEntry(&element.Static, rkentry.WithNameStaticFileHandlerEntry(element.Name))

		inters := make([]rest.Middleware, 0)

		// add global path ignorance
		rkmid.AddPathToIgnoreGlobal(element.Middleware.Ignore...)

		// logging middlewares
		if element.Middleware.Logging.Enabled {
			inters = append(inters, rkzerolog.Middleware(
				rkmidlog.ToOptions(&element.Middleware.Logging, element.Name, ZeroEntryType,
					loggerEntry, eventEntry)...))
		}

		// Default interceptor should be placed after logging middleware, we should make sure interceptors never panic
		// insert panic middleware
		inters = append(inters, rkzeropanic.Middleware(
			rkmidpanic.WithEntryNameAndType(element.Name, ZeroEntryType)))

		// metrics middleware
		if element.Middleware.Prom.Enabled {
			inters = append(inters, rkzeroprom.Middleware(
				rkmidprom.ToOptions(&element.Middleware.Prom, element.Name, ZeroEntryType,
					promRegistry, rkmidprom.LabelerTypeHttp)...))
		}

		// tracing middleware
		if element.Middleware.Trace.Enabled {
			inters = append(inters, rkzerotrace.Middleware(
				rkmidtrace.ToOptions(&element.Middleware.Trace, element.Name, ZeroEntryType)...))
		}

		// jwt middleware
		if element.Middleware.Jwt.Enabled {
			inters = append(inters, rkzerojwt.Middleware(
				rkmidjwt.ToOptions(&element.Middleware.Jwt, element.Name, ZeroEntryType)...))
		}

		// secure middleware
		if element.Middleware.Secure.Enabled {
			inters = append(inters, rkzerosec.Middleware(
				rkmidsec.ToOptions(&element.Middleware.Secure, element.Name, ZeroEntryType)...))
		}

		// csrf middleware
		if element.Middleware.Csrf.Enabled {
			inters = append(inters, rkzerocsrf.Middleware(
				rkmidcsrf.ToOptions(&element.Middleware.Csrf, element.Name, ZeroEntryType)...))
		}

		// cors middleware
		if element.Middleware.Cors.Enabled {
			inters = append(inters, rkzerocors.Middleware(
				rkmidcors.ToOptions(&element.Middleware.Cors, element.Name, ZeroEntryType)...))
		}

		// meta middleware
		if element.Middleware.Meta.Enabled {
			inters = append(inters, rkzerometa.Middleware(
				rkmidmeta.ToOptions(&element.Middleware.Meta, element.Name, ZeroEntryType)...))
		}

		// auth middlewares
		if element.Middleware.Auth.Enabled {
			inters = append(inters, rkzeroauth.Middleware(
				rkmidauth.ToOptions(&element.Middleware.Auth, element.Name, ZeroEntryType)...))
		}

		// rate limit middleware
		if element.Middleware.RateLimit.Enabled {
			inters = append(inters, rkzerolimit.Middleware(
				rkmidlimit.ToOptions(&element.Middleware.RateLimit, element.Name, ZeroEntryType)...))
		}

		entry := RegisterZeroEntry(
			WithName(name),
			WithDescription(element.Description),
			WithPort(element.Port),
			WithLoggerEntry(loggerEntry),
			WithEventEntry(eventEntry),
			WithCertEntry(certEntry),
			WithPromEntry(promEntry),
			WithDocsEntry(docsEntry),
			WithStaticFileHandlerEntry(staticEntry),
			WithCommonServiceEntry(commonServiceEntry),
			WithSwEntry(swEntry))

		entry.AddMiddleware(inters...)

		res[name] = entry
	}

	return res
}

// RegisterZeroEntry register ZeroEntry with options.
func RegisterZeroEntry(opts ...ZeroEntryOption) *ZeroEntry {
	entry := &ZeroEntry{
		entryType:        ZeroEntryType,
		entryDescription: "Internal RK entry which helps to bootstrap with go-zero framework.",
		Port:             8080,
		ServerRunOption:  make([]rest.RunOption, 0),
	}

	for i := range opts {
		opts[i](entry)
	}

	if entry.LoggerEntry == nil {
		entry.LoggerEntry = rkentry.NewLoggerEntryStdout()
	}

	if entry.EventEntry == nil {
		entry.EventEntry = rkentry.NewEventEntryStdout()
	}

	if len(entry.entryName) < 1 {
		entry.entryName = "zero-" + strconv.FormatUint(entry.Port, 10)
	}

	if entry.Server == nil {
		if entry.ServerConf != nil {
			entry.Server = rest.MustNewServer(*entry.ServerConf, entry.ServerRunOption...)
		} else {
			serverConf := rest.RestConf{
				Host: "0.0.0.0",
				Port: int(entry.Port),
			}
			serverConf.Name = entry.entryName
			// disable log
			serverConf.Log.Mode = "console"
			serverConf.Log.Level = "severe"
			serverConf.Telemetry.Sampler = 0
			entry.Server = rest.MustNewServer(serverConf, entry.ServerRunOption...)
		}
	}

	// Init TLS config
	if entry.IsTlsEnabled() {
		entry.TlsConfig = &tls.Config{
			InsecureSkipVerify: true,
			Certificates:       []tls.Certificate{*entry.CertEntry.Certificate},
		}

		rest.WithTLSConfig(entry.TlsConfig)(entry.Server)
	}

	// add entry name and entry type into loki syncer if enabled
	entry.LoggerEntry.AddEntryLabelToLokiSyncer(entry)
	entry.EventEntry.AddEntryLabelToLokiSyncer(entry)

	rkentry.GlobalAppCtx.AddEntry(entry)

	return entry
}

// Bootstrap ZeroEntry.
func (entry *ZeroEntry) Bootstrap(ctx context.Context) {
	event, _ := entry.logBasicInfo("Bootstrap", ctx)

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
			Path:    entry.CommonServiceEntry.ReadyPath,
			Handler: entry.CommonServiceEntry.Ready,
		})
		entry.Server.AddRoute(rest.Route{
			Method:  http.MethodGet,
			Path:    entry.CommonServiceEntry.AlivePath,
			Handler: entry.CommonServiceEntry.Alive,
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

		// Bootstrap common service entry.
		entry.CommonServiceEntry.Bootstrap(ctx)
	}

	// Is Docs enabled?
	if entry.IsDocsEnabled() {
		// Bootstrap Docs entry.
		entry.Server.AddRoute(rest.Route{
			Method:  http.MethodGet,
			Path:    path.Join(entry.DocsEntry.Path),
			Handler: entry.DocsEntry.ConfigFileHandler(),
		})
		entry.Server.AddRoute(rest.Route{
			Method:  http.MethodGet,
			Path:    path.Join(entry.DocsEntry.Path, ":*"),
			Handler: entry.DocsEntry.ConfigFileHandler(),
		})

		entry.DocsEntry.Bootstrap(ctx)
	}

	// Is Static enabled?
	if entry.IsStaticFileHandlerEnabled() {
		// Bootstrap Docs entry.
		entry.Server.AddRoute(rest.Route{
			Method:  http.MethodGet,
			Path:    path.Join(entry.StaticFileEntry.Path),
			Handler: entry.StaticFileEntry.GetFileHandler(),
		})
		entry.Server.AddRoute(rest.Route{
			Method:  http.MethodGet,
			Path:    path.Join(entry.StaticFileEntry.Path, ":*"),
			Handler: entry.StaticFileEntry.GetFileHandler(),
		})

		entry.StaticFileEntry.Bootstrap(ctx)
	}

	go func(zeroEntry *ZeroEntry) {
		if entry.Server != nil {
			entry.Server.Start()
		}
	}(entry)

	entry.bootstrapLogOnce.Do(func() {
		// Print link and logging message
		scheme := "http"
		if entry.IsTlsEnabled() {
			scheme = "https"
		}

		if entry.IsSwEnabled() {
			entry.LoggerEntry.Info(fmt.Sprintf("SwaggerEntry: %s://localhost:%d%s", scheme, entry.Port, entry.SwEntry.Path))
		}
		if entry.IsDocsEnabled() {
			entry.LoggerEntry.Info(fmt.Sprintf("DocsEntry: %s://localhost:%d%s", scheme, entry.Port, entry.DocsEntry.Path))
		}
		if entry.IsPromEnabled() {
			entry.LoggerEntry.Info(fmt.Sprintf("PromEntry: %s://localhost:%d%s", scheme, entry.Port, entry.PromEntry.Path))
		}
		if entry.IsStaticFileHandlerEnabled() {
			entry.LoggerEntry.Info(fmt.Sprintf("StaticFileHandlerEntry: %s://localhost:%d%s", scheme, entry.Port, entry.StaticFileEntry.Path))
		}
		if entry.IsCommonServiceEnabled() {
			handlers := []string{
				fmt.Sprintf("%s://localhost:%d%s", scheme, entry.Port, entry.CommonServiceEntry.ReadyPath),
				fmt.Sprintf("%s://localhost:%d%s", scheme, entry.Port, entry.CommonServiceEntry.AlivePath),
				fmt.Sprintf("%s://localhost:%d%s", scheme, entry.Port, entry.CommonServiceEntry.InfoPath),
			}

			entry.LoggerEntry.Info(fmt.Sprintf("CommonSreviceEntry: %s", strings.Join(handlers, ", ")))
		}
		entry.EventEntry.Finish(event)
	})
}

// Interrupt ZeroEntry.
func (entry *ZeroEntry) Interrupt(ctx context.Context) {
	event, _ := entry.logBasicInfo("Interrupt", ctx)

	if entry.IsSwEnabled() {
		entry.SwEntry.Interrupt(ctx)
	}

	if entry.IsPromEnabled() {
		entry.PromEntry.Interrupt(ctx)
	}

	if entry.IsCommonServiceEnabled() {
		entry.CommonServiceEntry.Interrupt(ctx)
	}

	if entry.IsDocsEnabled() {
		entry.DocsEntry.Interrupt(ctx)
	}

	if entry.IsStaticFileHandlerEnabled() {
		entry.StaticFileEntry.Interrupt(ctx)
	}

	if entry.Server != nil {
		entry.Server.Stop()
	}

	entry.EventEntry.Finish(event)
}

// GetName Get entry name.
func (entry *ZeroEntry) GetName() string {
	return entry.entryName
}

// GetType Get entry type.
func (entry *ZeroEntry) GetType() string {
	return entry.entryType
}

// GetDescription Get description of entry.
func (entry *ZeroEntry) GetDescription() string {
	return entry.entryDescription
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
		"name":                   entry.entryName,
		"type":                   entry.entryType,
		"description":            entry.entryDescription,
		"port":                   entry.Port,
		"swEntry":                entry.SwEntry,
		"docsEntry":              entry.DocsEntry,
		"commonServiceEntry":     entry.CommonServiceEntry,
		"promEntry":              entry.PromEntry,
		"staticFileHandlerEntry": entry.StaticFileEntry,
	}

	if entry.CertEntry != nil {
		m["certEntry"] = entry.CertEntry.GetName()
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
	entryRaw := rkentry.GlobalAppCtx.GetEntry(ZeroEntryType, name)
	if entryRaw == nil {
		return nil
	}

	entry, _ := entryRaw.(*ZeroEntry)
	return entry
}

// AddMiddleware Add interceptors.
// This function should be called before Bootstrap() called.
func (entry *ZeroEntry) AddMiddleware(inters ...rest.Middleware) {
	for i := range inters {
		entry.Server.Use(inters[i])

	}
}

// IsTlsEnabled Is TLS enabled?
func (entry *ZeroEntry) IsTlsEnabled() bool {
	return entry.CertEntry != nil && entry.CertEntry.Certificate != nil
}

// IsSwEnabled Is swagger entry enabled?
func (entry *ZeroEntry) IsSwEnabled() bool {
	return entry.SwEntry != nil
}

// IsCommonServiceEnabled Is common service entry enabled?
func (entry *ZeroEntry) IsCommonServiceEnabled() bool {
	return entry.CommonServiceEntry != nil
}

// IsDocsEnabled Is TV entry enabled?
func (entry *ZeroEntry) IsDocsEnabled() bool {
	return entry.DocsEntry != nil
}

// IsStaticFileHandlerEnabled Is static file handler entry enabled?
func (entry *ZeroEntry) IsStaticFileHandlerEnabled() bool {
	return entry.StaticFileEntry != nil
}

// IsPromEnabled Is prometheus entry enabled?
func (entry *ZeroEntry) IsPromEnabled() bool {
	return entry.PromEntry != nil
}

// ***************** Helper function *****************

// Add basic fields into event.
func (entry *ZeroEntry) logBasicInfo(operation string, ctx context.Context) (rkquery.Event, *zap.Logger) {
	event := entry.EventEntry.Start(
		operation,
		rkquery.WithEntryName(entry.GetName()),
		rkquery.WithEntryType(entry.GetType()))

	// extract eventId if exists
	if val := ctx.Value("eventId"); val != nil {
		if id, ok := val.(string); ok {
			event.SetEventId(id)
		}
	}

	logger := entry.LoggerEntry.Logger.With(
		zap.String("eventId", event.GetEventId()),
		zap.String("entryName", entry.entryName),
		zap.String("entryType", entry.entryType))

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
			zap.Bool("commonServiceEnabled", true))
	}

	// add TvEntry info
	if entry.IsDocsEnabled() {
		event.AddPayloads(
			zap.Bool("docsEnabled", true),
			zap.String("docsPath", entry.DocsEntry.Path))
	}

	// add PromEntry info
	if entry.IsPromEnabled() {
		event.AddPayloads(
			zap.Bool("promEnabled", true),
			zap.Uint64("promPort", entry.Port),
			zap.String("promPath", entry.PromEntry.Path))
	}

	// add StaticFileHandlerEntry info
	if entry.IsStaticFileHandlerEnabled() {
		event.AddPayloads(
			zap.Bool("staticFileHandlerEnabled", true),
			zap.String("staticFileHandlerPath", entry.StaticFileEntry.Path))
	}

	// add tls info
	if entry.IsTlsEnabled() {
		event.AddPayloads(
			zap.Bool("tlsEnabled", true))
	}

	logger.Info(fmt.Sprintf("%s zeroEntry", operation))

	return event, logger

}

// ***************** Options *****************

// ZeroEntryOption zero entry option.
type ZeroEntryOption func(*ZeroEntry)

// WithName provide name.
func WithName(name string) ZeroEntryOption {
	return func(entry *ZeroEntry) {
		entry.entryName = name
	}
}

// WithDescription provide name.
func WithDescription(description string) ZeroEntryOption {
	return func(entry *ZeroEntry) {
		entry.entryDescription = description
	}
}

// WithPort provide port.
func WithPort(port uint64) ZeroEntryOption {
	return func(entry *ZeroEntry) {
		entry.Port = port
	}
}

// WithLoggerEntry provide rkentry.LoggerEntry.
func WithLoggerEntry(logger *rkentry.LoggerEntry) ZeroEntryOption {
	return func(entry *ZeroEntry) {
		entry.LoggerEntry = logger
	}
}

// WithEventEntry provide rkentry.EventEntry.
func WithEventEntry(eventLogger *rkentry.EventEntry) ZeroEntryOption {
	return func(entry *ZeroEntry) {
		entry.EventEntry = eventLogger
	}
}

// WithCertEntry provide rkentry.CertEntry.
func WithCertEntry(certEntry *rkentry.CertEntry) ZeroEntryOption {
	return func(entry *ZeroEntry) {
		entry.CertEntry = certEntry
	}
}

// WithSwEntry provide SwEntry.
func WithSwEntry(sw *rkentry.SWEntry) ZeroEntryOption {
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

// WithStaticFileHandlerEntry provide CommonServiceEntry.
func WithStaticFileHandlerEntry(static *rkentry.StaticFileHandlerEntry) ZeroEntryOption {
	return func(entry *ZeroEntry) {
		entry.StaticFileEntry = static
	}
}

// WithMiddlewares provide user middlewares.
func WithMiddlewares(inters ...rest.Middleware) ZeroEntryOption {
	return func(entry *ZeroEntry) {
		if entry.Middlewares == nil {
			entry.Middlewares = make([]rest.Middleware, 0)
		}

		entry.Middlewares = append(entry.Middlewares, inters...)
	}
}

// WithPromEntry provide PromEntry.
func WithPromEntry(prom *rkentry.PromEntry) ZeroEntryOption {
	return func(entry *ZeroEntry) {
		entry.PromEntry = prom
	}
}

// WithDocsEntry provide TvEntry.
func WithDocsEntry(docsEntry *rkentry.DocsEntry) ZeroEntryOption {
	return func(entry *ZeroEntry) {
		entry.DocsEntry = docsEntry
	}
}

// WithServerConf provide *rest.RestConf.
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
