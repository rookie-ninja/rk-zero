// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

package rkzero

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/markbates/pkger"
	"github.com/markbates/pkger/pkging"
	"github.com/rookie-ninja/rk-common/common"
	"github.com/rookie-ninja/rk-entry/entry"
	"github.com/rookie-ninja/rk-query"
	rkzeroctx "github.com/rookie-ninja/rk-zero/interceptor/context"
	"github.com/tal-tech/go-zero/rest/pathvar"
	"go.uber.org/zap"
	"html/template"
	"io/ioutil"
	"net/http"
	"path"
	"strings"
	"time"
)

var (
	// Templates is a map to store go template
	Templates = map[string][]byte{}
)

const (
	// TvEntryType default entry type
	TvEntryType = "TvEntry"
	// TvEntryNameDefault default entry name
	TvEntryNameDefault = "TvDefault"
	// TvEntryDescription default entry description
	TvEntryDescription = "Internal RK entry which implements tv web with go-zero framework."
)

// Read go TV related template files into memory.
func init() {
	Templates["header"] = readFileFromPkger("/assets/tv/header.tmpl")
	Templates["footer"] = readFileFromPkger("/assets/tv/footer.tmpl")
	Templates["aside"] = readFileFromPkger("/assets/tv/aside.tmpl")
	Templates["head"] = readFileFromPkger("/assets/tv/head.tmpl")
	Templates["svg-sprite"] = readFileFromPkger("/assets/tv/svg-sprite.tmpl")
	Templates["overview"] = readFileFromPkger("/assets/tv/overview.tmpl")
	Templates["apis"] = readFileFromPkger("/assets/tv/apis.tmpl")
	Templates["entries"] = readFileFromPkger("/assets/tv/entries.tmpl")
	Templates["configs"] = readFileFromPkger("/assets/tv/configs.tmpl")
	Templates["certs"] = readFileFromPkger("/assets/tv/certs.tmpl")
	Templates["not-found"] = readFileFromPkger("/assets/tv/not-found.tmpl")
	Templates["internal-error"] = readFileFromPkger("/assets/tv/internal-error.tmpl")
	Templates["os"] = readFileFromPkger("/assets/tv/os.tmpl")
	Templates["env"] = readFileFromPkger("/assets/tv/env.tmpl")
	Templates["prometheus"] = readFileFromPkger("/assets/tv/prometheus.tmpl")
	Templates["deps"] = readFileFromPkger("/assets/tv/deps.tmpl")
	Templates["license"] = readFileFromPkger("/assets/tv/license.tmpl")
	Templates["info"] = readFileFromPkger("/assets/tv/info.tmpl")
	Templates["logs"] = readFileFromPkger("/assets/tv/logs.tmpl")
	Templates["git"] = readFileFromPkger("/assets/tv/git.tmpl")
}

// Read go template files with Pkger.
func readFileFromPkger(filePath string) []byte {
	var file pkging.File
	var err error

	if file, err = pkger.Open(path.Join("github.com/rookie-ninja/rk-zero:/boot", filePath)); err != nil {
		return []byte{}
	}

	var bytes []byte
	if bytes, err = ioutil.ReadAll(file); err != nil {
		return []byte{}
	}

	return bytes
}

// BootConfigTv Bootstrap config of tv.
// 1: Enabled: Enable tv service.
type BootConfigTv struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
}

// TvEntry RK TV entry supports web UI for application & process information.
// 1: EntryName: Name of entry.
// 2: EntryType: Type of entry.
// 2: EntryDescription: Description of entry.
// 3: ZapLoggerEntry: ZapLoggerEntry used for logging.
// 4: EventLoggerEntry: EventLoggerEntry used for logging.
// 5: Template: GO template for rendering web UI.
type TvEntry struct {
	EntryName        string                    `json:"entryName" yaml:"entryName"`
	EntryType        string                    `json:"entryType" yaml:"entryType"`
	EntryDescription string                    `json:"entryDescription" yaml:"entryDescription"`
	ZapLoggerEntry   *rkentry.ZapLoggerEntry   `json:"zapLoggerEntry" yaml:"zapLoggerEntry"`
	EventLoggerEntry *rkentry.EventLoggerEntry `json:"eventLoggerEntry" yaml:"eventLoggerEntry"`
	Template         *template.Template        `json:"-" yaml:"-"`
}

// TvEntryOption TV entry option.
type TvEntryOption func(entry *TvEntry)

// WithNameTv Provide name.
func WithNameTv(name string) TvEntryOption {
	return func(entry *TvEntry) {
		entry.EntryName = name
	}
}

// WithEventLoggerEntryTv Provide rkentry.EventLoggerEntry.
func WithEventLoggerEntryTv(eventLoggerEntry *rkentry.EventLoggerEntry) TvEntryOption {
	return func(entry *TvEntry) {
		entry.EventLoggerEntry = eventLoggerEntry
	}
}

// WithZapLoggerEntryTv Provide rkentry.ZapLoggerEntry.
func WithZapLoggerEntryTv(zapLoggerEntry *rkentry.ZapLoggerEntry) TvEntryOption {
	return func(entry *TvEntry) {
		entry.ZapLoggerEntry = zapLoggerEntry
	}
}

// NewTvEntry Create new TV entry with options.
func NewTvEntry(opts ...TvEntryOption) *TvEntry {
	entry := &TvEntry{
		EntryName:        TvEntryNameDefault,
		EntryType:        TvEntryType,
		EntryDescription: TvEntryDescription,
		ZapLoggerEntry:   rkentry.GlobalAppCtx.GetZapLoggerEntryDefault(),
		EventLoggerEntry: rkentry.GlobalAppCtx.GetEventLoggerEntryDefault(),
	}

	for i := range opts {
		opts[i](entry)
	}

	if len(entry.EntryName) < 1 {
		entry.EntryName = TvEntryNameDefault
	}

	return entry
}

// AssetsFileHandler Handler which returns js, css, images and html files for TV web UI.
func (entry *TvEntry) AssetsFileHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/rk/v1"), "/")

		if file, err := pkger.Open(path.Join("/boot", p)); err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		} else {
			http.ServeContent(w, r, path.Base(p), time.Now(), file)
		}
	}
}

// Bootstrap TV entry.
// Rendering bellow templates.
// 1: head.tmpl
// 2: header.tmpl
// 3: footer.tmpl
// 4: aside.tmpl
// 5: svg-sprite.tmpl
// 6: overview.tmpl
// 7: apis.tmpl
// 8: entries.tmpl
// 9: configs.tmpl
// 10: certs.tmpl
// 11: os.tmpl
// 12: env.tmpl
// 13: prometheus.tmpl
// 14: logs.tmpl
// 15: deps.tmpl
// 16: license.tmpl
// 17: info.tmpl
func (entry *TvEntry) Bootstrap(ctx context.Context) {
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

	event.AddPayloads(zap.String("path", "/rk/v1/tv/*item"))

	entry.Template = template.New("rk-tv")

	// Parse templates
	for k, v := range Templates {
		if _, err := entry.Template.Parse(string(v)); err != nil {
			entry.EventLoggerEntry.GetEventHelper().FinishWithError(event, err)
			entry.ZapLoggerEntry.GetLogger().Error(fmt.Sprintf("Error occurs while parsing %s template.", k))
			rkcommon.ShutdownWithError(err)
		}
	}

	logger.Info("Bootstrapping tvEntry.", event.ListPayloads()...)

	entry.EventLoggerEntry.GetEventHelper().Finish(event)
}

// Interrupt TV entry.
func (entry *TvEntry) Interrupt(ctx context.Context) {
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

	logger.Info("Interrupting TvEntry.", event.ListPayloads()...)
}

// GetName Get name of entry.
func (entry *TvEntry) GetName() string {
	return entry.EntryName
}

// GetType Get type of entry.
func (entry *TvEntry) GetType() string {
	return entry.EntryType
}

// GetDescription Get description of entry.
func (entry *TvEntry) GetDescription() string {
	return entry.EntryDescription
}

// String Stringfy entry.
func (entry *TvEntry) String() string {
	bytesStr, _ := json.Marshal(entry)
	return string(bytesStr)
}

// MarshalJSON Marshal entry
func (entry *TvEntry) MarshalJSON() ([]byte, error) {
	m := map[string]interface{}{
		"entryName":        entry.EntryName,
		"entryType":        entry.EntryType,
		"entryDescription": entry.EntryDescription,
		"eventLoggerEntry": entry.EventLoggerEntry.GetName(),
		"zapLoggerEntry":   entry.ZapLoggerEntry.GetName(),
	}

	return json.Marshal(&m)
}

// UnmarshalJSON Not supported.
func (entry *TvEntry) UnmarshalJSON([]byte) error {
	return nil
}

// Add basic fields into event.
func (entry *TvEntry) logBasicInfo(event rkquery.Event) {
	event.AddPayloads(
		zap.String("entryName", entry.EntryName),
		zap.String("entryType", entry.EntryType),
	)
}

// TV handler
// @Summary Get HTML page of /tv/
// @Id 15
// @version 1.0
// @Security ApiKeyAuth
// @Security BasicAuth
// @produce text/html
// @Success 200 string HTML
// @Router /rk/v1/tv/ [get]
func (entry *TvEntry) TV(writer http.ResponseWriter, req *http.Request) {
	logger := rkzeroctx.GetLogger(req, writer)

	param := pathvar.Vars(req)

	writer.Header().Set("Content-Type", "text/html;charset=UTF-8")

	switch item := param["*"]; item {
	case "", "/", "/overview", "/application":
		buf := entry.doExecuteTemplate("overview", doReadme(writer, req), logger)
		writer.WriteHeader(http.StatusOK)
		writer.Write(buf.Bytes())
	case "entries":
		buf := entry.doExecuteTemplate("entries", doEntries(writer, req), logger)
		writer.WriteHeader(http.StatusOK)
		writer.Write(buf.Bytes())
	case "configs":
		buf := entry.doExecuteTemplate("configs", doConfigs(writer, req), logger)
		writer.WriteHeader(http.StatusOK)
		writer.Write(buf.Bytes())
	case "certs":
		buf := entry.doExecuteTemplate("certs", doCerts(writer, req), logger)
		writer.WriteHeader(http.StatusOK)
		writer.Write(buf.Bytes())
	case "os":
		buf := entry.doExecuteTemplate("os", doSys(writer, req), logger)
		writer.WriteHeader(http.StatusOK)
		writer.Write(buf.Bytes())
	case "env":
		buf := entry.doExecuteTemplate("env", doSys(writer, req), logger)
		writer.WriteHeader(http.StatusOK)
		writer.Write(buf.Bytes())
	case "logs":
		buf := entry.doExecuteTemplate("logs", doLogs(writer, req), logger)
		writer.WriteHeader(http.StatusOK)
		writer.Write(buf.Bytes())
	case "deps":
		buf := entry.doExecuteTemplate("deps", doDeps(writer, req), logger)
		writer.WriteHeader(http.StatusOK)
		writer.Write(buf.Bytes())
	case "license":
		buf := entry.doExecuteTemplate("license", doLicense(writer, req), logger)
		writer.WriteHeader(http.StatusOK)
		writer.Write(buf.Bytes())
	case "info":
		buf := entry.doExecuteTemplate("info", doInfo(writer, req), logger)
		writer.WriteHeader(http.StatusOK)
		writer.Write(buf.Bytes())
	case "git":
		buf := entry.doExecuteTemplate("git", doGit(writer, req), logger)
		writer.WriteHeader(http.StatusOK)
		writer.Write(buf.Bytes())
	default:
		buf := entry.doExecuteTemplate("not-found", nil, logger)
		writer.WriteHeader(http.StatusOK)
		writer.Write(buf.Bytes())
	}
}

// Execute go template into buffer.
func (entry *TvEntry) doExecuteTemplate(templateName string, data interface{}, logger *zap.Logger) *bytes.Buffer {
	buf := new(bytes.Buffer)

	if err := entry.Template.ExecuteTemplate(buf, templateName, data); err != nil {
		logger.Warn("Failed to execute template", zap.Error(err))
		buf.Reset()
		entry.Template.ExecuteTemplate(buf, "internal-error", nil)
	}

	return buf
}