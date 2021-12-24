// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

package rkzero

import (
	"context"
	"github.com/rookie-ninja/rk-entry/entry"
	rkzerolog "github.com/rookie-ninja/rk-zero/interceptor/log/zap"
	rkzerometrics "github.com/rookie-ninja/rk-zero/interceptor/metrics/prom"
	"github.com/stretchr/testify/assert"
	"github.com/tal-tech/go-zero/rest"
	"io/ioutil"
	"net"
	"os"
	"path"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

const (
	defaultBootConfigStr = `
---
zero:
 - name: greeter
   port: 8080
   enabled: true
   sw:
     enabled: true
     path: "sw"
   commonService:
     enabled: true
   tv:
     enabled: true
   prom:
     enabled: true
     pusher:
       enabled: false
   interceptors:
     loggingZap:
       enabled: true
     metricsProm:
       enabled: true
     auth:
       enabled: true
       basic:
         - "user:pass"
     meta:
       enabled: true
     tracingTelemetry:
       enabled: true
     ratelimit:
       enabled: true
     timeout:
       enabled: true
     cors:
       enabled: true
     jwt:
       enabled: true
     secure:
       enabled: true
     csrf:
       enabled: true
 - name: greeter2
   port: 2008
   enabled: true
   sw:
     enabled: true
     path: "sw"
   commonService:
     enabled: true
   tv:
     enabled: true
   interceptors:
     loggingZap:
       enabled: true
     metricsProm:
       enabled: true
     auth:
       enabled: true
       basic:
         - "user:pass"
`
)

func TestWithZapLoggerEntryZero_HappyCase(t *testing.T) {
	loggerEntry := rkentry.NoopZapLoggerEntry()
	entry := RegisterZeroEntry()

	option := WithZapLoggerEntryZero(loggerEntry)
	option(entry)

	assert.Equal(t, loggerEntry, entry.ZapLoggerEntry)
}

func TestWithEventLoggerEntryZero_HappyCase(t *testing.T) {
	entry := RegisterZeroEntry()

	eventLoggerEntry := rkentry.NoopEventLoggerEntry()

	option := WithEventLoggerEntryZero(eventLoggerEntry)
	option(entry)

	assert.Equal(t, eventLoggerEntry, entry.EventLoggerEntry)
}

func TestWithInterceptorsZero_WithNilInterceptorList(t *testing.T) {
	entry := RegisterZeroEntry()

	option := WithInterceptorsZero(nil)
	option(entry)

	assert.NotNil(t, entry.Interceptors)
}

func TestWithInterceptorsZero_HappyCase(t *testing.T) {
	entry := RegisterZeroEntry()

	loggingInterceptor := rkzerolog.Interceptor()
	metricsInterceptor := rkzerometrics.Interceptor()

	interceptors := []rest.Middleware{
		loggingInterceptor,
		metricsInterceptor,
	}

	option := WithInterceptorsZero(interceptors...)
	option(entry)

	assert.NotNil(t, entry.Interceptors)
	// should contains logging, metrics and panic interceptor
	// where panic interceptor is inject by default
	assert.Len(t, entry.Interceptors, 3)
}

func TestWithCommonServiceEntryZero_WithEntry(t *testing.T) {
	entry := RegisterZeroEntry()

	option := WithCommonServiceEntryZero(NewCommonServiceEntry())
	option(entry)

	assert.NotNil(t, entry.CommonServiceEntry)
}

func TestWithCommonServiceEntryZero_WithoutEntry(t *testing.T) {
	entry := RegisterZeroEntry()

	assert.Nil(t, entry.CommonServiceEntry)
}

func TestWithTVEntryZero_WithEntry(t *testing.T) {
	entry := RegisterZeroEntry()

	option := WithTVEntryZero(NewTvEntry())
	option(entry)

	assert.NotNil(t, entry.TvEntry)
}

func TestWithTVEntry_WithoutEntry(t *testing.T) {
	entry := RegisterZeroEntry()

	assert.Nil(t, entry.TvEntry)
}

func TestWithCertEntryZero_HappyCase(t *testing.T) {
	entry := RegisterZeroEntry()
	certEntry := &rkentry.CertEntry{}

	option := WithCertEntryZero(certEntry)
	option(entry)

	assert.Equal(t, entry.CertEntry, certEntry)
}

func TestWithSWEntryZero_HappyCase(t *testing.T) {
	entry := RegisterZeroEntry()
	sw := NewSwEntry()

	option := WithSwEntryZero(sw)
	option(entry)

	assert.Equal(t, entry.SwEntry, sw)
}

func TestWithPortZero_HappyCase(t *testing.T) {
	entry := RegisterZeroEntry()
	port := uint64(1111)

	option := WithPortZero(port)
	option(entry)

	assert.Equal(t, entry.Port, port)
}

func TestWithNameZero_HappyCase(t *testing.T) {
	entry := RegisterZeroEntry()
	name := "unit-test-entry"

	option := WithNameZero(name)
	option(entry)

	assert.Equal(t, entry.EntryName, name)
}

func TestRegisterZeroEntriesWithConfig_WithInvalidConfigFilePath(t *testing.T) {
	defer assertPanic(t)

	RegisterZeroEntriesWithConfig("/invalid-path")
}

func TestRegisterZeroEntriesWithConfig_WithNilFactory(t *testing.T) {
	defer assertNotPanic(t)

	// write config file in unit test temp directory
	tempDir := path.Join(t.TempDir(), "boot.yaml")
	assert.Nil(t, ioutil.WriteFile(tempDir, []byte(defaultBootConfigStr), os.ModePerm))
	entries := RegisterZeroEntriesWithConfig(tempDir)
	assert.NotNil(t, entries)
	assert.Len(t, entries, 2)
	for _, entry := range entries {
		entry.Interrupt(context.TODO())
	}
}

func TestRegisterZeroEntriesWithConfig_HappyCase(t *testing.T) {
	defer assertNotPanic(t)

	// write config file in unit test temp directory
	tempDir := path.Join(t.TempDir(), "boot.yaml")
	assert.Nil(t, ioutil.WriteFile(tempDir, []byte(defaultBootConfigStr), os.ModePerm))
	entries := RegisterZeroEntriesWithConfig(tempDir)
	assert.NotNil(t, entries)
	assert.Len(t, entries, 2)

	// validate entry element based on boot.yaml config defined in defaultBootConfigStr
	greeter := entries["greeter"].(*ZeroEntry)
	assert.NotNil(t, greeter)
	assert.Equal(t, uint64(8080), greeter.Port)
	assert.NotNil(t, greeter.SwEntry)
	assert.NotNil(t, greeter.CommonServiceEntry)
	assert.NotNil(t, greeter.TvEntry)
	// logging, metrics, auth and panic interceptor should be included
	assert.True(t, len(greeter.Interceptors) > 0)

	greeter2 := entries["greeter2"].(*ZeroEntry)
	assert.NotNil(t, greeter2)
	assert.Equal(t, uint64(2008), greeter2.Port)
	assert.NotNil(t, greeter2.SwEntry)
	assert.NotNil(t, greeter2.CommonServiceEntry)
	assert.NotNil(t, greeter2.TvEntry)
	// logging, metrics, auth and panic interceptor should be included
	assert.Len(t, greeter2.Interceptors, 4)

	for _, entry := range entries {
		entry.Interrupt(context.TODO())
	}
}

func TestRegisterZeroEntry_WithZapLoggerEntry(t *testing.T) {
	loggerEntry := rkentry.NoopZapLoggerEntry()
	entry := RegisterZeroEntry(WithZapLoggerEntryZero(loggerEntry))
	assert.Equal(t, loggerEntry, entry.ZapLoggerEntry)
}

func TestRegisterZeroEntry_WithEventLoggerEntry(t *testing.T) {
	loggerEntry := rkentry.NoopEventLoggerEntry()

	entry := RegisterZeroEntry(WithEventLoggerEntryZero(loggerEntry))
	assert.Equal(t, loggerEntry, entry.EventLoggerEntry)
}

func TestNewZeroEntry_WithInterceptors(t *testing.T) {
	loggingInterceptor := rkzerolog.Interceptor()
	entry := RegisterZeroEntry(WithInterceptorsZero(loggingInterceptor))
	assert.Len(t, entry.Interceptors, 2)
}

func TestNewZeroEntry_WithCommonServiceEntry(t *testing.T) {
	entry := RegisterZeroEntry(WithCommonServiceEntryZero(NewCommonServiceEntry()))
	assert.NotNil(t, entry.CommonServiceEntry)
}

func TestNewZeroEntry_WithTVEntry(t *testing.T) {
	entry := RegisterZeroEntry(WithTVEntryZero(NewTvEntry()))
	assert.NotNil(t, entry.TvEntry)
}

func TestNewZeroEntry_WithCertStore(t *testing.T) {
	certEntry := &rkentry.CertEntry{}

	entry := RegisterZeroEntry(WithCertEntryZero(certEntry))
	assert.Equal(t, certEntry, entry.CertEntry)
}

func TestNewZeroEntry_WithSWEntry(t *testing.T) {
	sw := NewSwEntry()
	entry := RegisterZeroEntry(WithSwEntryZero(sw))
	assert.Equal(t, sw, entry.SwEntry)
}

func TestNewZeroEntry_WithPort(t *testing.T) {
	entry := RegisterZeroEntry(WithPortZero(8080))
	assert.Equal(t, uint64(8080), entry.Port)
}

func TestNewZeroEntry_WithName(t *testing.T) {
	entry := RegisterZeroEntry(WithNameZero("unit-test-greeter"))
	assert.Equal(t, "unit-test-greeter", entry.GetName())
}

func TestNewZeroEntry_WithDefaultValue(t *testing.T) {
	entry := RegisterZeroEntry()
	assert.True(t, strings.HasPrefix(entry.GetName(), "ZeroServer-"))
	assert.NotNil(t, entry.ZapLoggerEntry)
	assert.NotNil(t, entry.EventLoggerEntry)
	assert.Len(t, entry.Interceptors, 1)
	assert.NotNil(t, entry.Server)
	assert.Nil(t, entry.SwEntry)
	assert.Nil(t, entry.CertEntry)
	assert.False(t, entry.IsSwEnabled())
	assert.False(t, entry.IsTlsEnabled())
	assert.Nil(t, entry.CommonServiceEntry)
	assert.Nil(t, entry.TvEntry)
	assert.Equal(t, "ZeroEntry", entry.GetType())
}

func TestZeroEntry_GetName_HappyCase(t *testing.T) {
	entry := RegisterZeroEntry(WithNameZero("unit-test-entry"))
	assert.Equal(t, "unit-test-entry", entry.GetName())
}

func TestZeroEntry_GetType_HappyCase(t *testing.T) {
	assert.Equal(t, "ZeroEntry", RegisterZeroEntry().GetType())
}

func TestZeroEntry_String_HappyCase(t *testing.T) {
	assert.NotEmpty(t, RegisterZeroEntry().String())
}

func TestZeroEntry_IsSwEnabled_ExpectTrue(t *testing.T) {
	sw := NewSwEntry()
	entry := RegisterZeroEntry(WithSwEntryZero(sw))
	assert.True(t, entry.IsSwEnabled())
}

func TestZeroEntry_IsSwEnabled_ExpectFalse(t *testing.T) {
	entry := RegisterZeroEntry()
	assert.False(t, entry.IsSwEnabled())
}

func TestZeroEntry_IsTlsEnabled_ExpectTrue(t *testing.T) {
	certEntry := &rkentry.CertEntry{
		Store: &rkentry.CertStore{},
	}

	entry := RegisterZeroEntry(WithCertEntryZero(certEntry))
	assert.True(t, entry.IsTlsEnabled())
}

func TestZeroEntry_IsTlsEnabled_ExpectFalse(t *testing.T) {
	entry := RegisterZeroEntry()
	assert.False(t, entry.IsTlsEnabled())
}

func TestZeroEntry_GetZero_HappyCase(t *testing.T) {
	entry := RegisterZeroEntry()
	assert.NotNil(t, entry.Server)
}

func TestZeroEntry_Bootstrap_WithSwagger(t *testing.T) {
	sw := NewSwEntry(
		WithPathSw("sw"),
		WithZapLoggerEntrySw(rkentry.NoopZapLoggerEntry()),
		WithEventLoggerEntrySw(rkentry.NoopEventLoggerEntry()))
	entry := RegisterZeroEntry(
		WithNameZero("unit-test-entry"),
		WithPortZero(8080),
		WithZapLoggerEntryZero(rkentry.NoopZapLoggerEntry()),
		WithEventLoggerEntryZero(rkentry.NoopEventLoggerEntry()),
		WithSwEntryZero(sw))

	go entry.Bootstrap(context.Background())
	time.Sleep(time.Second)
	// endpoint should be accessible with 8080 port
	validateServerIsUp(t, entry.Port)

	entry.Interrupt(context.Background())
	time.Sleep(time.Second)

	// force to kill it because go-zero do not stop server with stop() call
	syscall.Kill(syscall.Getpid(), syscall.SIGTERM)
}

//func TestZeroEntry_Bootstrap_WithoutSwagger(t *testing.T) {
//	entry := RegisterZeroEntry(
//		WithNameZero("unit-test-entry"),
//		WithPortZero(8080),
//		WithZapLoggerEntryZero(rkentry.NoopZapLoggerEntry()),
//		WithEventLoggerEntryZero(rkentry.NoopEventLoggerEntry()))
//
//	go entry.Bootstrap(context.Background())
//	time.Sleep(time.Second)
//	// endpoint should be accessible with 8080 port
//	validateServerIsUp(t, entry.Port)
//
//	entry.Interrupt(context.Background())
//	time.Sleep(time.Second)
//
//	// force to kill it because go-zero do not stop server with stop() call
//	syscall.Kill(syscall.Getpid(), syscall.SIGTERM)
//}
//
//func TestZeroEntry_Bootstrap_WithoutTLS(t *testing.T) {
//	entry := RegisterZeroEntry(
//		WithNameZero("unit-test-entry"),
//		WithPortZero(8080),
//		WithZapLoggerEntryZero(rkentry.NoopZapLoggerEntry()),
//		WithEventLoggerEntryZero(rkentry.NoopEventLoggerEntry()))
//
//	go entry.Bootstrap(context.Background())
//	time.Sleep(time.Second)
//	// endpoint should be accessible with 8080 port
//	validateServerIsUp(t, entry.Port)
//
//	entry.Interrupt(context.Background())
//	time.Sleep(time.Second)
//
//	// force to kill it because go-zero do not stop server with stop() call
//	syscall.Kill(syscall.Getpid(), syscall.SIGTERM)
//}
//
//func TestZeroEntry_Shutdown_WithBootstrap(t *testing.T) {
//	defer assertNotPanic(t)
//
//	entry := RegisterZeroEntry(
//		WithNameZero("unit-test-entry"),
//		WithPortZero(8080),
//		WithZapLoggerEntryZero(rkentry.NoopZapLoggerEntry()),
//		WithEventLoggerEntryZero(rkentry.NoopEventLoggerEntry()))
//
//	go entry.Bootstrap(context.Background())
//	time.Sleep(time.Second)
//	// endpoint should be accessible with 8080 port
//	validateServerIsUp(t, entry.Port)
//
//	entry.Interrupt(context.Background())
//	time.Sleep(time.Second)
//
//	// force to kill it because go-zero do not stop server with stop() call
//	syscall.Kill(syscall.Getpid(), syscall.SIGTERM)
//}
//
//func TestZeroEntry_Shutdown_WithoutBootstrap(t *testing.T) {
//	defer assertNotPanic(t)
//
//	entry := RegisterZeroEntry(
//		WithNameZero("unit-test-entry"),
//		WithPortZero(8080),
//		WithZapLoggerEntryZero(rkentry.NoopZapLoggerEntry()),
//		WithEventLoggerEntryZero(rkentry.NoopEventLoggerEntry()))
//
//	entry.Interrupt(context.Background())
//	time.Sleep(time.Second)
//
//	// force to kill it because go-zero do not stop server with stop() call
//	syscall.Kill(syscall.Getpid(), syscall.SIGTERM)
//}

func validateServerIsUp(t *testing.T, port uint64) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("0.0.0.0", strconv.FormatUint(port, 10)), time.Second)
	assert.Nil(t, err)
	assert.NotNil(t, conn)
	if conn != nil {
		assert.Nil(t, conn.Close())
	}
}
