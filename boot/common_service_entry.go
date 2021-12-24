// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

package rkzero

import (
	"context"
	"encoding/json"
	"github.com/rookie-ninja/rk-common/error"
	"github.com/rookie-ninja/rk-entry/entry"
	"github.com/rookie-ninja/rk-query"
	rkzeroctx "github.com/rookie-ninja/rk-zero/interceptor/context"
	"github.com/tal-tech/go-zero/rest/httpx"
	"go.uber.org/zap"
	"net/http"
	"path"
	"runtime"
)

const (
	// CommonServiceEntryType type of entry
	CommonServiceEntryType = "CommonServiceEntry"
	// CommonServiceEntryNameDefault name of entry
	CommonServiceEntryNameDefault = "CommonServiceDefault"
	// CommonServiceEntryDescription description of entry
	CommonServiceEntryDescription = "Internal RK entry which implements commonly used API with go-zero framework."
)

var (
	internalError = rkerror.New(rkerror.WithHttpCode(http.StatusInternalServerError))
)

// @title RK Common Service
// @version 1.0
// @description This is builtin RK common service.

// @contact.name rk-dev
// @contact.url https://github.com/rookie-ninja/rk-zero
// @contact.email lark@pointgoal.io

// @license.name Apache 2.0 License
// @license.url https://github.com/rookie-ninja/rk-zero/blob/master/LICENSE.txt

// @securityDefinitions.basic BasicAuth

// @securityDefinitions.apikey ApiKeyAuth
// @in header
// @name X-API-Key

// @securityDefinitions.apikey JWT
// @in header
// @name Authorization

// @schemes http https

// BootConfigCommonService Bootstrap config of common service.
// 1: Enabled: Enable common service.
type BootConfigCommonService struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
}

// CommonServiceEntry RK common service which contains commonly used APIs
// 1: Healthy Returns true if process is alive
// 2: Gc Trigger gc()
// 3: Info Returns entry basic information
// 4: Configs Returns viper configs in GlobalAppCtx
// 5: Apis Returns list of apis registered in go-zero router
// 6: Sys Returns CPU and Memory information
// 7: Req Returns request metrics
// 8: Certs Returns certificates
// 9: Entries Returns entries
// 10: Logs Returns log entries
// 12: Deps Returns dependency which is full  go.mod file content
// 13: License Returns license file content
// 14: Readme Returns README file content
type CommonServiceEntry struct {
	EntryName        string                    `json:"entryName" yaml:"entryName"`
	EntryType        string                    `json:"entryType" yaml:"entryType"`
	EntryDescription string                    `json:"entryDescription" yaml:"entryDescription"`
	EventLoggerEntry *rkentry.EventLoggerEntry `json:"-" yaml:"-"`
	ZapLoggerEntry   *rkentry.ZapLoggerEntry   `json:"-" yaml:"-"`
}

// CommonServiceEntryOption Common service entry option.
type CommonServiceEntryOption func(*CommonServiceEntry)

// WithNameCommonService Provide name.
func WithNameCommonService(name string) CommonServiceEntryOption {
	return func(entry *CommonServiceEntry) {
		entry.EntryName = name
	}
}

// WithEventLoggerEntryCommonService Provide rkentry.EventLoggerEntry.
func WithEventLoggerEntryCommonService(eventLoggerEntry *rkentry.EventLoggerEntry) CommonServiceEntryOption {
	return func(entry *CommonServiceEntry) {
		entry.EventLoggerEntry = eventLoggerEntry
	}
}

// WithZapLoggerEntryCommonService Provide rkentry.ZapLoggerEntry.
func WithZapLoggerEntryCommonService(zapLoggerEntry *rkentry.ZapLoggerEntry) CommonServiceEntryOption {
	return func(entry *CommonServiceEntry) {
		entry.ZapLoggerEntry = zapLoggerEntry
	}
}

// NewCommonServiceEntry Create new common service entry with options.
func NewCommonServiceEntry(opts ...CommonServiceEntryOption) *CommonServiceEntry {
	entry := &CommonServiceEntry{
		EntryName:        CommonServiceEntryNameDefault,
		EntryType:        CommonServiceEntryType,
		EntryDescription: CommonServiceEntryDescription,
		ZapLoggerEntry:   rkentry.GlobalAppCtx.GetZapLoggerEntryDefault(),
		EventLoggerEntry: rkentry.GlobalAppCtx.GetEventLoggerEntryDefault(),
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
		entry.EntryName = CommonServiceEntryNameDefault
	}

	return entry
}

// Bootstrap common service entry.
func (entry *CommonServiceEntry) Bootstrap(ctx context.Context) {
	// No op
	event := entry.EventLoggerEntry.GetEventHelper().Start(
		"bootstrap",
		rkquery.WithEntryName(entry.EntryName),
		rkquery.WithEntryType(entry.EntryType))

	logger := entry.ZapLoggerEntry.GetLogger()

	if raw := ctx.Value(bootstrapEventIdKey); raw != nil {
		event.SetEventId(raw.(string))
		logger = logger.With(zap.String("eventId", event.GetEventId()))
	}

	entry.logBasicInfo(event)

	defer entry.EventLoggerEntry.GetEventHelper().Finish(event)

	logger.Info("Bootstrapping CommonServiceEntry.", event.ListPayloads()...)
}

// Interrupt common service entry.
func (entry *CommonServiceEntry) Interrupt(ctx context.Context) {
	event := entry.EventLoggerEntry.GetEventHelper().Start(
		"interrupt",
		rkquery.WithEntryName(entry.EntryName),
		rkquery.WithEntryType(entry.EntryType))

	logger := entry.ZapLoggerEntry.GetLogger()

	if raw := ctx.Value(bootstrapEventIdKey); raw != nil {
		event.SetEventId(raw.(string))
		logger = logger.With(zap.String("eventId", event.GetEventId()))
	}

	entry.logBasicInfo(event)

	defer entry.EventLoggerEntry.GetEventHelper().Finish(event)

	logger.Info("Interrupting CommonServiceEntry.", event.ListPayloads()...)
}

// GetName Get name of entry.
func (entry *CommonServiceEntry) GetName() string {
	return entry.EntryName
}

// GetType Get entry type.
func (entry *CommonServiceEntry) GetType() string {
	return entry.EntryType
}

// String Stringfy entry.
func (entry *CommonServiceEntry) String() string {
	bytes, _ := json.Marshal(entry)
	return string(bytes)
}

// GetDescription Get description of entry.
func (entry *CommonServiceEntry) GetDescription() string {
	return entry.EntryDescription
}

// MarshalJSON Marshal entry.
func (entry *CommonServiceEntry) MarshalJSON() ([]byte, error) {
	m := map[string]interface{}{
		"entryName":        entry.EntryName,
		"entryType":        entry.EntryType,
		"entryDescription": entry.EntryDescription,
		"zapLoggerEntry":   entry.ZapLoggerEntry.GetName(),
		"eventLoggerEntry": entry.EventLoggerEntry.GetName(),
	}

	return json.Marshal(&m)
}

// UnmarshalJSON Not supported.
func (entry *CommonServiceEntry) UnmarshalJSON([]byte) error {
	return nil
}

// Add basic fields into event.
func (entry *CommonServiceEntry) logBasicInfo(event rkquery.Event) {
	event.AddPayloads(
		zap.String("entryName", entry.EntryName),
		zap.String("entryType", entry.EntryType),
	)
}

// Helper function of /healthy call.
func doHealthy(writer http.ResponseWriter, req *http.Request) *rkentry.HealthyResponse {
	return &rkentry.HealthyResponse{
		Healthy: true,
	}
}

// Healthy handler
// @Summary Get application healthy status
// @Id 1
// @version 1.0
// @Security ApiKeyAuth
// @Security BasicAuth
// @Security JWT
// @produce application/json
// @Success 200 {object} rkentry.HealthyResponse
// @Router /rk/v1/healthy [get]
func (entry *CommonServiceEntry) Healthy(writer http.ResponseWriter, req *http.Request) {
	httpx.WriteJson(writer, http.StatusOK, doHealthy(writer, req))
}

// Helper function of /gc
func doGc(writer http.ResponseWriter, req *http.Request) *rkentry.GcResponse {
	before := rkentry.NewMemInfo()
	runtime.GC()
	after := rkentry.NewMemInfo()

	return &rkentry.GcResponse{
		MemStatBeforeGc: before,
		MemStatAfterGc:  after,
	}
}

// Gc handler
// @Summary Trigger Gc
// @Id 2
// @version 1.0
// @Security ApiKeyAuth
// @Security BasicAuth
// @Security JWT
// @produce application/json
// @Success 200 {object} rkentry.GcResponse
// @Router /rk/v1/gc [get]
func (entry *CommonServiceEntry) Gc(writer http.ResponseWriter, req *http.Request) {
	httpx.WriteJson(writer, http.StatusOK, doGc(writer, req))
}

// Helper function of /info
func doInfo(writer http.ResponseWriter, req *http.Request) *rkentry.ProcessInfo {
	return rkentry.NewProcessInfo()
}

// Info handler
// @Summary Get application and process info
// @Id 3
// @version 1.0
// @Security ApiKeyAuth
// @Security BasicAuth
// @Security JWT
// @produce application/json
// @Success 200 {object} rkentry.ProcessInfo
// @Router /rk/v1/info [get]
func (entry *CommonServiceEntry) Info(writer http.ResponseWriter, req *http.Request) {
	httpx.WriteJson(writer, http.StatusOK, doInfo(writer, req))
}

// Helper function of /configs
func doConfigs(writer http.ResponseWriter, req *http.Request) *rkentry.ConfigsResponse {
	res := &rkentry.ConfigsResponse{
		Entries: make([]*rkentry.ConfigsResponse_ConfigEntry, 0),
	}

	for _, v := range rkentry.GlobalAppCtx.ListConfigEntries() {
		configEntry := &rkentry.ConfigsResponse_ConfigEntry{
			EntryName:        v.GetName(),
			EntryType:        v.GetType(),
			EntryDescription: v.GetDescription(),
			EntryMeta:        v.GetViperAsMap(),
			Path:             v.Path,
		}

		res.Entries = append(res.Entries, configEntry)
	}

	return res
}

// Configs handler
// @Summary List ConfigEntry
// @Id 4
// @version 1.0
// @Security ApiKeyAuth
// @Security BasicAuth
// @Security JWT
// @produce application/json
// @Success 200 {object} rkentry.ConfigsResponse
// @Router /rk/v1/configs [get]
func (entry *CommonServiceEntry) Configs(writer http.ResponseWriter, req *http.Request) {
	httpx.WriteJson(writer, http.StatusOK, doConfigs(writer, req))
}

// Helper function of /sys
func doSys(writer http.ResponseWriter, req *http.Request) *rkentry.SysResponse {
	return &rkentry.SysResponse{
		CpuInfo:   rkentry.NewCpuInfo(),
		MemInfo:   rkentry.NewMemInfo(),
		NetInfo:   rkentry.NewNetInfo(),
		OsInfo:    rkentry.NewOsInfo(),
		GoEnvInfo: rkentry.NewGoEnvInfo(),
	}
}

// Sys handler
// @Summary Get OS Stat
// @Id 6
// @version 1.0
// @Security ApiKeyAuth
// @Security BasicAuth
// @Security JWT
// @produce application/json
// @Success 200 {object} rkentry.SysResponse
// @Router /rk/v1/sys [get]
func (entry *CommonServiceEntry) Sys(writer http.ResponseWriter, req *http.Request) {
	httpx.WriteJson(writer, http.StatusOK, doSys(writer, req))
}

// Helper function of /entries
func doEntriesHelper(m map[string]rkentry.Entry, res *rkentry.EntriesResponse) {
	// Iterate entries and construct EntryElement
	for i := range m {
		entry := m[i]
		element := &rkentry.EntriesResponse_Entry{
			EntryName:        entry.GetName(),
			EntryType:        entry.GetType(),
			EntryDescription: entry.GetDescription(),
			EntryMeta:        entry,
		}

		if entries, ok := res.Entries[entry.GetType()]; ok {
			entries = append(entries, element)
		} else {
			res.Entries[entry.GetType()] = []*rkentry.EntriesResponse_Entry{element}
		}
	}
}

// Helper function of /entries
func doEntries(writer http.ResponseWriter, req *http.Request) *rkentry.EntriesResponse {
	res := &rkentry.EntriesResponse{
		Entries: make(map[string][]*rkentry.EntriesResponse_Entry),
	}

	// Iterate all internal and external entries in GlobalAppCtx
	doEntriesHelper(rkentry.GlobalAppCtx.ListEntries(), res)
	doEntriesHelper(rkentry.GlobalAppCtx.ListEventLoggerEntriesRaw(), res)
	doEntriesHelper(rkentry.GlobalAppCtx.ListZapLoggerEntriesRaw(), res)
	doEntriesHelper(rkentry.GlobalAppCtx.ListConfigEntriesRaw(), res)
	doEntriesHelper(rkentry.GlobalAppCtx.ListCertEntriesRaw(), res)
	doEntriesHelper(rkentry.GlobalAppCtx.ListCredEntriesRaw(), res)

	// App info entry
	appInfoEntry := rkentry.GlobalAppCtx.GetAppInfoEntry()
	res.Entries[appInfoEntry.GetType()] = []*rkentry.EntriesResponse_Entry{
		{
			EntryName:        appInfoEntry.GetName(),
			EntryType:        appInfoEntry.GetType(),
			EntryDescription: appInfoEntry.GetDescription(),
			EntryMeta:        appInfoEntry,
		},
	}

	return res
}

// Entries handler
// @Summary List all Entry
// @Id 8
// @version 1.0
// @Security ApiKeyAuth
// @Security BasicAuth
// @Security JWT
// @produce application/json
// @Success 200 {object} rkentry.EntriesResponse
// @Router /rk/v1/entries [get]
func (entry *CommonServiceEntry) Entries(writer http.ResponseWriter, req *http.Request) {
	httpx.WriteJson(writer, http.StatusOK, doEntries(writer, req))
}

// Helper function of /entries
func doCerts(writer http.ResponseWriter, req *http.Request) *rkentry.CertsResponse {
	res := &rkentry.CertsResponse{
		Entries: make([]*rkentry.CertsResponse_Entry, 0),
	}

	entries := rkentry.GlobalAppCtx.ListCertEntries()

	// Iterator cert entries and construct CertResponse
	for i := range entries {
		entry := entries[i]

		certEntry := &rkentry.CertsResponse_Entry{
			EntryName:        entry.GetName(),
			EntryType:        entry.GetType(),
			EntryDescription: entry.GetDescription(),
		}

		if entry.Retriever != nil {
			certEntry.Endpoint = entry.Retriever.GetEndpoint()
			certEntry.Locale = entry.Retriever.GetLocale()
			certEntry.Provider = entry.Retriever.GetProvider()
			certEntry.ServerCertPath = entry.ServerCertPath
			certEntry.ServerKeyPath = entry.ServerKeyPath
			certEntry.ClientCertPath = entry.ClientCertPath
			certEntry.ClientKeyPath = entry.ClientKeyPath
		}

		if entry.Store != nil {
			certEntry.ServerCert = entry.Store.SeverCertString()
			certEntry.ClientCert = entry.Store.ClientCertString()
		}

		res.Entries = append(res.Entries, certEntry)
	}

	return res
}

// Certs handler
// @Summary List CertEntry
// @Id 9
// @version 1.0
// @Security ApiKeyAuth
// @Security BasicAuth
// @Security JWT
// @produce application/json
// @Success 200 {object} rkentry.CertsResponse
// @Router /rk/v1/certs [get]
func (entry *CommonServiceEntry) Certs(writer http.ResponseWriter, req *http.Request) {
	httpx.WriteJson(writer, http.StatusOK, doCerts(writer, req))
}

// Helper function of /logs
func doLogsHelper(m map[string]rkentry.Entry, res *rkentry.LogsResponse) {
	entries := make([]*rkentry.LogsResponse_Entry, 0)

	// Iterate logger related entries and construct LogEntryElement
	for i := range m {
		entry := m[i]
		logEntry := &rkentry.LogsResponse_Entry{
			EntryName:        entry.GetName(),
			EntryType:        entry.GetType(),
			EntryDescription: entry.GetDescription(),
			EntryMeta:        entry,
		}

		if val, ok := entry.(*rkentry.ZapLoggerEntry); ok {
			if val.LoggerConfig != nil {
				logEntry.OutputPaths = val.LoggerConfig.OutputPaths
				logEntry.ErrorOutputPaths = val.LoggerConfig.ErrorOutputPaths
			}
		}

		if val, ok := entry.(*rkentry.EventLoggerEntry); ok {
			if val.LoggerConfig != nil {
				logEntry.OutputPaths = val.LoggerConfig.OutputPaths
				logEntry.ErrorOutputPaths = val.LoggerConfig.ErrorOutputPaths
			}
		}

		entries = append(entries, logEntry)
	}

	var entryType string

	if len(entries) > 0 {
		entryType = entries[0].EntryType
	}

	res.Entries[entryType] = entries
}

// Helper function of /logs
func doLogs(writer http.ResponseWriter, req *http.Request) *rkentry.LogsResponse {
	res := &rkentry.LogsResponse{
		Entries: make(map[string][]*rkentry.LogsResponse_Entry),
	}

	doLogsHelper(rkentry.GlobalAppCtx.ListEventLoggerEntriesRaw(), res)
	doLogsHelper(rkentry.GlobalAppCtx.ListZapLoggerEntriesRaw(), res)

	return res
}

// Logs handler
// @Summary List logger related entries
// @Id 10
// @version 1.0
// @Security ApiKeyAuth
// @Security BasicAuth
// @Security JWT
// @produce application/json
// @Success 200 {object} rkentry.LogsResponse
// @Router /rk/v1/logs [get]
func (entry *CommonServiceEntry) Logs(writer http.ResponseWriter, req *http.Request) {
	httpx.WriteJson(writer, http.StatusOK, doLogs(writer, req))
}

// Extract zero entry from zap middleware
func getEntry(req *http.Request) *ZeroEntry {
	if req == nil {
		return nil
	}

	entryRaw := rkentry.GlobalAppCtx.GetEntry(rkzeroctx.GetEntryName(req))
	if entryRaw == nil {
		return nil
	}

	entry, _ := entryRaw.(*ZeroEntry)
	return entry
}

// Deps handler
// @Summary List dependencies related application
// @Id 11
// @version 1.0
// @Security ApiKeyAuth
// @Security BasicAuth
// @Security JWT
// @produce application/json
// @Success 200 {object} rkentry.DepResponse
// @Router /rk/v1/deps [get]
func (entry *CommonServiceEntry) Deps(writer http.ResponseWriter, req *http.Request) {
	httpx.WriteJson(writer, http.StatusOK, doDeps(writer, req))
}

// Extract zero entry from zap middleware
func doDeps(writer http.ResponseWriter, req *http.Request) *rkentry.DepResponse {
	res := &rkentry.DepResponse{}

	appInfoEntry := rkentry.GlobalAppCtx.GetAppInfoEntry()
	if appInfoEntry == nil {
		return res
	}

	res.GoMod = appInfoEntry.GoMod

	return res
}

// License handler
// @Summary Get license related application
// @Id 12
// @version 1.0
// @Security ApiKeyAuth
// @Security BasicAuth
// @Security JWT
// @produce application/json
// @Success 200 {object} rkentry.LicenseResponse
// @Router /rk/v1/license [get]
func (entry *CommonServiceEntry) License(writer http.ResponseWriter, req *http.Request) {
	httpx.WriteJson(writer, http.StatusOK, doLicense(writer, req))
}

// Extract zero entry from zap middleware
func doLicense(writer http.ResponseWriter, req *http.Request) *rkentry.LicenseResponse {
	res := &rkentry.LicenseResponse{}

	appInfoEntry := rkentry.GlobalAppCtx.GetAppInfoEntry()
	if appInfoEntry == nil {
		return res
	}

	res.License = appInfoEntry.License

	return res
}

// Readme handler
// @Summary Get README file.
// @Id 13
// @version 1.0
// @Security ApiKeyAuth
// @Security BasicAuth
// @Security JWT
// @produce application/json
// @Success 200 {object} rkentry.ReadmeResponse
// @Router /rk/v1/readme [get]
func (entry *CommonServiceEntry) Readme(writer http.ResponseWriter, req *http.Request) {
	httpx.WriteJson(writer, http.StatusOK, doReadme(writer, req))
}

// Extract zero entry from zap middleware
func doReadme(writer http.ResponseWriter, req *http.Request) *rkentry.ReadmeResponse {
	res := &rkentry.ReadmeResponse{}

	appInfoEntry := rkentry.GlobalAppCtx.GetAppInfoEntry()
	if appInfoEntry == nil {
		return res
	}

	res.Readme = appInfoEntry.Readme

	return res
}

// Git handler
// @Summary Get Git information.
// @Id 14
// @version 1.0
// @Security ApiKeyAuth
// @Security BasicAuth
// @Security JWT
// @produce application/json
// @Success 200 {object} rkentry.GitResponse
// @Router /rk/v1/git [get]
func (entry *CommonServiceEntry) Git(writer http.ResponseWriter, req *http.Request) {
	httpx.WriteJson(writer, http.StatusOK, doGit(writer, req))
}

// Extract zero entry from zap middleware
func doGit(writer http.ResponseWriter, req *http.Request) *rkentry.GitResponse {
	res := &rkentry.GitResponse{}

	rkMetaEntry := rkentry.GlobalAppCtx.GetRkMetaEntry()
	if rkMetaEntry == nil {
		return res
	}

	res.Package = path.Base(rkMetaEntry.RkMeta.Git.Url)
	res.Branch = rkMetaEntry.RkMeta.Git.Branch
	res.Tag = rkMetaEntry.RkMeta.Git.Tag
	res.Url = rkMetaEntry.RkMeta.Git.Url
	res.CommitId = rkMetaEntry.RkMeta.Git.Commit.Id
	res.CommitIdAbbr = rkMetaEntry.RkMeta.Git.Commit.IdAbbr
	res.CommitSub = rkMetaEntry.RkMeta.Git.Commit.Sub
	res.CommitterName = rkMetaEntry.RkMeta.Git.Commit.Committer.Name
	res.CommitterEmail = rkMetaEntry.RkMeta.Git.Commit.Committer.Email
	res.CommitDate = rkMetaEntry.RkMeta.Git.Commit.Date

	return res
}