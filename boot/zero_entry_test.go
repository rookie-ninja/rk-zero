// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

package rkzero

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	rkentry "github.com/rookie-ninja/rk-entry/entry"
	rkzerometa "github.com/rookie-ninja/rk-zero/interceptor/meta"
	"github.com/stretchr/testify/assert"
	"github.com/tal-tech/go-zero/rest"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"path"
	"strconv"
	"syscall"
	"testing"
	"time"
)

const (
	defaultBootConfigStr = `
---
zero:
 - name: greeter
   port: 1949
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
     gzip:
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
 - name: greeter3
   port: 2022
   enabled: false
`
)

//func TestWithZapLoggerEntryZero_HappyCase(t *testing.T) {
//	loggerEntry := rkentry.NoopZapLoggerEntry()
//	entry := RegisterZeroEntry()
//
//	option := WithZapLoggerEntryZero(loggerEntry)
//	option(entry)
//
//	assert.Equal(t, loggerEntry, entry.ZapLoggerEntry)
//}
//
//func TestWithEventLoggerEntryZero_HappyCase(t *testing.T) {
//	entry := RegisterZeroEntry()
//
//	eventLoggerEntry := rkentry.NoopEventLoggerEntry()
//
//	option := WithEventLoggerEntryZero(eventLoggerEntry)
//	option(entry)
//
//	assert.Equal(t, eventLoggerEntry, entry.EventLoggerEntry)
//}
//
//func TestWithInterceptorsZero_WithNilInterceptorList(t *testing.T) {
//	entry := RegisterZeroEntry()
//
//	option := WithInterceptorsZero(nil)
//	option(entry)
//
//	assert.NotNil(t, entry.Interceptors)
//}
//
//func TestWithInterceptorsZero_HappyCase(t *testing.T) {
//	entry := RegisterZeroEntry()
//
//	loggingInterceptor := rkzerolog.Interceptor()
//	metricsInterceptor := rkzerometrics.Interceptor()
//
//	interceptors := []rest.Middleware{
//		loggingInterceptor,
//		metricsInterceptor,
//	}
//
//	option := WithInterceptorsZero(interceptors...)
//	option(entry)
//
//	assert.NotNil(t, entry.Interceptors)
//	// should contains logging, metrics and panic interceptor
//	// where panic interceptor is inject by default
//	assert.Len(t, entry.Interceptors, 3)
//}
//
//func TestWithCommonServiceEntryZero_WithEntry(t *testing.T) {
//	entry := RegisterZeroEntry()
//
//	option := WithCommonServiceEntryZero(NewCommonServiceEntry())
//	option(entry)
//
//	assert.NotNil(t, entry.CommonServiceEntry)
//}
//
//func TestWithCommonServiceEntryZero_WithoutEntry(t *testing.T) {
//	entry := RegisterZeroEntry()
//
//	assert.Nil(t, entry.CommonServiceEntry)
//}
//
//func TestWithTVEntryZero_WithEntry(t *testing.T) {
//	entry := RegisterZeroEntry()
//
//	option := WithTVEntryZero(NewTvEntry())
//	option(entry)
//
//	assert.NotNil(t, entry.TvEntry)
//}
//
//func TestWithTVEntry_WithoutEntry(t *testing.T) {
//	entry := RegisterZeroEntry()
//
//	assert.Nil(t, entry.TvEntry)
//}
//
//func TestWithCertEntryZero_HappyCase(t *testing.T) {
//	entry := RegisterZeroEntry()
//	certEntry := &rkentry.CertEntry{}
//
//	option := WithCertEntryZero(certEntry)
//	option(entry)
//
//	assert.Equal(t, entry.CertEntry, certEntry)
//}
//
//func TestWithSWEntryZero_HappyCase(t *testing.T) {
//	entry := RegisterZeroEntry()
//	sw := NewSwEntry()
//
//	option := WithSwEntryZero(sw)
//	option(entry)
//
//	assert.Equal(t, entry.SwEntry, sw)
//}
//
//func TestWithPortZero_HappyCase(t *testing.T) {
//	entry := RegisterZeroEntry()
//	port := uint64(1111)
//
//	option := WithPortZero(port)
//	option(entry)
//
//	assert.Equal(t, entry.Port, port)
//}
//
//func TestWithNameZero_HappyCase(t *testing.T) {
//	entry := RegisterZeroEntry()
//	name := "unit-test-entry"
//
//	option := WithNameZero(name)
//	option(entry)
//
//	assert.Equal(t, entry.EntryName, name)
//}
//
//func TestRegisterZeroEntriesWithConfig_WithInvalidConfigFilePath(t *testing.T) {
//	defer assertPanic(t)
//
//	RegisterZeroEntriesWithConfig("/invalid-path")
//}
//
//func TestRegisterZeroEntriesWithConfig_WithNilFactory(t *testing.T) {
//	defer assertNotPanic(t)
//
//	// write config file in unit test temp directory
//	tempDir := path.Join(t.TempDir(), "boot.yaml")
//	assert.Nil(t, ioutil.WriteFile(tempDir, []byte(defaultBootConfigStr), os.ModePerm))
//	entries := RegisterZeroEntriesWithConfig(tempDir)
//	assert.NotNil(t, entries)
//	assert.Len(t, entries, 2)
//	for _, entry := range entries {
//		entry.Interrupt(context.TODO())
//	}
//}
//
//func TestRegisterZeroEntriesWithConfig_HappyCase(t *testing.T) {
//	defer assertNotPanic(t)
//
//	// write config file in unit test temp directory
//	tempDir := path.Join(t.TempDir(), "boot.yaml")
//	assert.Nil(t, ioutil.WriteFile(tempDir, []byte(defaultBootConfigStr), os.ModePerm))
//	entries := RegisterZeroEntriesWithConfig(tempDir)
//	assert.NotNil(t, entries)
//	assert.Len(t, entries, 2)
//
//	// validate entry element based on boot.yaml config defined in defaultBootConfigStr
//	greeter := entries["greeter"].(*ZeroEntry)
//	assert.NotNil(t, greeter)
//	assert.Equal(t, uint64(8080), greeter.Port)
//	assert.NotNil(t, greeter.SwEntry)
//	assert.NotNil(t, greeter.CommonServiceEntry)
//	assert.NotNil(t, greeter.TvEntry)
//	// logging, metrics, auth and panic interceptor should be included
//	assert.True(t, len(greeter.Interceptors) > 0)
//
//	greeter2 := entries["greeter2"].(*ZeroEntry)
//	assert.NotNil(t, greeter2)
//	assert.Equal(t, uint64(2008), greeter2.Port)
//	assert.NotNil(t, greeter2.SwEntry)
//	assert.NotNil(t, greeter2.CommonServiceEntry)
//	assert.NotNil(t, greeter2.TvEntry)
//	// logging, metrics, auth and panic interceptor should be included
//	assert.Len(t, greeter2.Interceptors, 4)
//
//	for _, entry := range entries {
//		entry.Interrupt(context.TODO())
//	}
//}
//
//func TestRegisterZeroEntry_WithZapLoggerEntry(t *testing.T) {
//	loggerEntry := rkentry.NoopZapLoggerEntry()
//	entry := RegisterZeroEntry(WithZapLoggerEntryZero(loggerEntry))
//	assert.Equal(t, loggerEntry, entry.ZapLoggerEntry)
//}
//
//func TestRegisterZeroEntry_WithEventLoggerEntry(t *testing.T) {
//	loggerEntry := rkentry.NoopEventLoggerEntry()
//
//	entry := RegisterZeroEntry(WithEventLoggerEntryZero(loggerEntry))
//	assert.Equal(t, loggerEntry, entry.EventLoggerEntry)
//}
//
//func TestNewZeroEntry_WithInterceptors(t *testing.T) {
//	loggingInterceptor := rkzerolog.Interceptor()
//	entry := RegisterZeroEntry(WithInterceptorsZero(loggingInterceptor))
//	assert.Len(t, entry.Interceptors, 2)
//}
//
//func TestNewZeroEntry_WithCommonServiceEntry(t *testing.T) {
//	entry := RegisterZeroEntry(WithCommonServiceEntryZero(NewCommonServiceEntry()))
//	assert.NotNil(t, entry.CommonServiceEntry)
//}
//
//func TestNewZeroEntry_WithTVEntry(t *testing.T) {
//	entry := RegisterZeroEntry(WithTVEntryZero(NewTvEntry()))
//	assert.NotNil(t, entry.TvEntry)
//}
//
//func TestNewZeroEntry_WithCertStore(t *testing.T) {
//	certEntry := &rkentry.CertEntry{}
//
//	entry := RegisterZeroEntry(WithCertEntryZero(certEntry))
//	assert.Equal(t, certEntry, entry.CertEntry)
//}
//
//func TestNewZeroEntry_WithSWEntry(t *testing.T) {
//	sw := NewSwEntry()
//	entry := RegisterZeroEntry(WithSwEntryZero(sw))
//	assert.Equal(t, sw, entry.SwEntry)
//}
//
//func TestNewZeroEntry_WithPort(t *testing.T) {
//	entry := RegisterZeroEntry(WithPortZero(8080))
//	assert.Equal(t, uint64(8080), entry.Port)
//}
//
//func TestNewZeroEntry_WithName(t *testing.T) {
//	entry := RegisterZeroEntry(WithNameZero("unit-test-greeter"))
//	assert.Equal(t, "unit-test-greeter", entry.GetName())
//}
//
//func TestNewZeroEntry_WithDefaultValue(t *testing.T) {
//	entry := RegisterZeroEntry()
//	assert.True(t, strings.HasPrefix(entry.GetName(), "ZeroServer-"))
//	assert.NotNil(t, entry.ZapLoggerEntry)
//	assert.NotNil(t, entry.EventLoggerEntry)
//	assert.Len(t, entry.Interceptors, 1)
//	assert.NotNil(t, entry.Server)
//	assert.Nil(t, entry.SwEntry)
//	assert.Nil(t, entry.CertEntry)
//	assert.False(t, entry.IsSwEnabled())
//	assert.False(t, entry.IsTlsEnabled())
//	assert.Nil(t, entry.CommonServiceEntry)
//	assert.Nil(t, entry.TvEntry)
//	assert.Equal(t, "ZeroEntry", entry.GetType())
//}
//
//func TestZeroEntry_GetName_HappyCase(t *testing.T) {
//	entry := RegisterZeroEntry(WithNameZero("unit-test-entry"))
//	assert.Equal(t, "unit-test-entry", entry.GetName())
//}
//
//func TestZeroEntry_GetType_HappyCase(t *testing.T) {
//	assert.Equal(t, "ZeroEntry", RegisterZeroEntry().GetType())
//}
//
//func TestZeroEntry_String_HappyCase(t *testing.T) {
//	assert.NotEmpty(t, RegisterZeroEntry().String())
//}
//
//func TestZeroEntry_IsSwEnabled_ExpectTrue(t *testing.T) {
//	sw := NewSwEntry()
//	entry := RegisterZeroEntry(WithSwEntryZero(sw))
//	assert.True(t, entry.IsSwEnabled())
//}
//
//func TestZeroEntry_IsSwEnabled_ExpectFalse(t *testing.T) {
//	entry := RegisterZeroEntry()
//	assert.False(t, entry.IsSwEnabled())
//}
//
//func TestZeroEntry_IsTlsEnabled_ExpectTrue(t *testing.T) {
//	certEntry := &rkentry.CertEntry{
//		Store: &rkentry.CertStore{},
//	}
//
//	entry := RegisterZeroEntry(WithCertEntryZero(certEntry))
//	assert.True(t, entry.IsTlsEnabled())
//}
//
//func TestZeroEntry_IsTlsEnabled_ExpectFalse(t *testing.T) {
//	entry := RegisterZeroEntry()
//	assert.False(t, entry.IsTlsEnabled())
//}
//
//func TestZeroEntry_GetZero_HappyCase(t *testing.T) {
//	entry := RegisterZeroEntry()
//	assert.NotNil(t, entry.Server)
//}
//
//func TestZeroEntry_Bootstrap_WithSwagger(t *testing.T) {
//	sw := NewSwEntry(
//		WithPathSw("sw"),
//		WithZapLoggerEntrySw(rkentry.NoopZapLoggerEntry()),
//		WithEventLoggerEntrySw(rkentry.NoopEventLoggerEntry()))
//	entry := RegisterZeroEntry(
//		WithNameZero("unit-test-entry"),
//		WithPortZero(8080),
//		WithZapLoggerEntryZero(rkentry.NoopZapLoggerEntry()),
//		WithEventLoggerEntryZero(rkentry.NoopEventLoggerEntry()),
//		WithSwEntryZero(sw))
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
////func TestZeroEntry_Bootstrap_WithoutSwagger(t *testing.T) {
////	entry := RegisterZeroEntry(
////		WithNameZero("unit-test-entry"),
////		WithPortZero(8080),
////		WithZapLoggerEntryZero(rkentry.NoopZapLoggerEntry()),
////		WithEventLoggerEntryZero(rkentry.NoopEventLoggerEntry()))
////
////	go entry.Bootstrap(context.Background())
////	time.Sleep(time.Second)
////	// endpoint should be accessible with 8080 port
////	validateServerIsUp(t, entry.Port)
////
////	entry.Interrupt(context.Background())
////	time.Sleep(time.Second)
////
////	// force to kill it because go-zero do not stop server with stop() call
////	syscall.Kill(syscall.Getpid(), syscall.SIGTERM)
////}
////
////func TestZeroEntry_Bootstrap_WithoutTLS(t *testing.T) {
////	entry := RegisterZeroEntry(
////		WithNameZero("unit-test-entry"),
////		WithPortZero(8080),
////		WithZapLoggerEntryZero(rkentry.NoopZapLoggerEntry()),
////		WithEventLoggerEntryZero(rkentry.NoopEventLoggerEntry()))
////
////	go entry.Bootstrap(context.Background())
////	time.Sleep(time.Second)
////	// endpoint should be accessible with 8080 port
////	validateServerIsUp(t, entry.Port)
////
////	entry.Interrupt(context.Background())
////	time.Sleep(time.Second)
////
////	// force to kill it because go-zero do not stop server with stop() call
////	syscall.Kill(syscall.Getpid(), syscall.SIGTERM)
////}
////
////func TestZeroEntry_Shutdown_WithBootstrap(t *testing.T) {
////	defer assertNotPanic(t)
////
////	entry := RegisterZeroEntry(
////		WithNameZero("unit-test-entry"),
////		WithPortZero(8080),
////		WithZapLoggerEntryZero(rkentry.NoopZapLoggerEntry()),
////		WithEventLoggerEntryZero(rkentry.NoopEventLoggerEntry()))
////
////	go entry.Bootstrap(context.Background())
////	time.Sleep(time.Second)
////	// endpoint should be accessible with 8080 port
////	validateServerIsUp(t, entry.Port)
////
////	entry.Interrupt(context.Background())
////	time.Sleep(time.Second)
////
////	// force to kill it because go-zero do not stop server with stop() call
////	syscall.Kill(syscall.Getpid(), syscall.SIGTERM)
////}
////
////func TestZeroEntry_Shutdown_WithoutBootstrap(t *testing.T) {
////	defer assertNotPanic(t)
////
////	entry := RegisterZeroEntry(
////		WithNameZero("unit-test-entry"),
////		WithPortZero(8080),
////		WithZapLoggerEntryZero(rkentry.NoopZapLoggerEntry()),
////		WithEventLoggerEntryZero(rkentry.NoopEventLoggerEntry()))
////
////	entry.Interrupt(context.Background())
////	time.Sleep(time.Second)
////
////	// force to kill it because go-zero do not stop server with stop() call
////	syscall.Kill(syscall.Getpid(), syscall.SIGTERM)
////}

func TestGetZeroEntry(t *testing.T) {
	// expect nil
	assert.Nil(t, GetZeroEntry("entry-name"))

	// happy case
	echoEntry := RegisterZeroEntry(WithName("ut"))
	assert.Equal(t, echoEntry, GetZeroEntry("ut"))

	rkentry.GlobalAppCtx.RemoveEntry("ut")
}

func TestRegisterZeroEntry(t *testing.T) {
	// without options
	entry := RegisterZeroEntry()
	assert.NotNil(t, entry)
	assert.NotEmpty(t, entry.GetName())
	assert.NotEmpty(t, entry.GetType())
	assert.NotEmpty(t, entry.GetDescription())
	assert.NotEmpty(t, entry.String())
	rkentry.GlobalAppCtx.RemoveEntry(entry.GetName())

	// with options
	serverConf := rest.RestConf{
		Host: "0.0.0.0",
		Port: int(entry.Port),
	}
	serverConf.Name = entry.EntryName
	// disable log
	serverConf.Log.Mode = "console"
	serverConf.Log.Level = "severe"
	serverConf.Telemetry.Sampler = 0

	entry = RegisterZeroEntry(
		WithZapLoggerEntry(nil),
		WithEventLoggerEntry(nil),
		WithCommonServiceEntry(rkentry.RegisterCommonServiceEntry()),
		WithTvEntry(rkentry.RegisterTvEntry()),
		WithCertEntry(rkentry.RegisterCertEntry()),
		WithSwEntry(rkentry.RegisterSwEntry()),
		WithPort(8080),
		WithName("ut-entry"),
		WithDescription("ut-desc"),
		WithPromEntry(rkentry.RegisterPromEntry()),
		WithServerConf(&serverConf),
		WithServerRunOption(rest.WithCors()))

	assert.NotEmpty(t, entry.GetName())
	assert.NotEmpty(t, entry.GetType())
	assert.NotEmpty(t, entry.GetDescription())
	assert.NotEmpty(t, entry.String())
	assert.True(t, entry.IsSwEnabled())
	assert.True(t, entry.IsPromEnabled())
	assert.True(t, entry.IsCommonServiceEnabled())
	assert.True(t, entry.IsTvEnabled())
	assert.True(t, entry.IsTlsEnabled())
	assert.NotNil(t, entry.ServerConf)
	assert.NotEmpty(t, entry.ServerRunOption)

	bytes, err := entry.MarshalJSON()
	assert.NotEmpty(t, bytes)
	assert.Nil(t, err)
	assert.Nil(t, entry.UnmarshalJSON([]byte{}))
}

func TestEchoEntry_AddInterceptor(t *testing.T) {
	defer assertNotPanic(t)
	entry := RegisterZeroEntry()
	inter := rkzerometa.Interceptor()
	entry.AddInterceptor(inter)
}

func TestEchoEntry_Bootstrap(t *testing.T) {
	defer assertNotPanic(t)

	// without enable sw, static, prom, common, tv, tls
	entry := RegisterZeroEntry(WithPort(8080))
	go entry.Bootstrap(context.Background())
	time.Sleep(time.Second)
	validateServerIsUp(t, 8080, entry.IsTlsEnabled())
	entry.Interrupt(context.Background())
	time.Sleep(time.Second)
	entry.Interrupt(context.TODO())
	// force to kill it because go-zero do not stop server with stop() call
	syscall.Kill(syscall.Getpid(), syscall.SIGTERM)

	entry = RegisterZeroEntry(
		WithPort(8080),
		WithCommonServiceEntry(rkentry.RegisterCommonServiceEntry()),
		WithTvEntry(rkentry.RegisterTvEntry()),
		WithSwEntry(rkentry.RegisterSwEntry()),
		WithPromEntry(rkentry.RegisterPromEntry()))
	go entry.Bootstrap(context.Background())
	time.Sleep(time.Second)
	validateServerIsUp(t, 8080, entry.IsTlsEnabled())
	entry.Interrupt(context.TODO())
	// force to kill it because go-zero do not stop server with stop() call
	syscall.Kill(syscall.Getpid(), syscall.SIGTERM)
}

func TestRegisterZeroEntriesWithConfig(t *testing.T) {
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

	greeter2 := entries["greeter2"].(*ZeroEntry)
	assert.NotNil(t, greeter2)

	greeter3 := entries["greeter3"]
	assert.Nil(t, greeter3)
}

func generateCerts() ([]byte, []byte) {
	// Create certs and return as []byte
	ca := &x509.Certificate{
		Subject: pkix.Name{
			Organization: []string{"Fake cert."},
		},
		SerialNumber:          big.NewInt(42),
		NotAfter:              time.Now().Add(2 * time.Hour),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// Create a Private Key
	key, _ := rsa.GenerateKey(rand.Reader, 4096)

	// Use CA Cert to sign a CSR and create a Public Cert
	csr := &key.PublicKey
	cert, _ := x509.CreateCertificate(rand.Reader, ca, ca, csr, key)

	// Convert keys into pem.Block
	c := &pem.Block{Type: "CERTIFICATE", Bytes: cert}
	k := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}

	return pem.EncodeToMemory(c), pem.EncodeToMemory(k)
}

func validateServerIsUp(t *testing.T, port uint64, isTls bool) {
	// sleep for 2 seconds waiting server startup
	time.Sleep(2 * time.Second)

	if !isTls {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort("0.0.0.0", strconv.FormatUint(port, 10)), time.Second)
		assert.Nil(t, err)
		assert.NotNil(t, conn)
		if conn != nil {
			assert.Nil(t, conn.Close())
		}
		return
	}

	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
	}

	tlsConn, err := tls.Dial("tcp", net.JoinHostPort("0.0.0.0", strconv.FormatUint(port, 10)), tlsConf)
	assert.Nil(t, err)
	assert.NotNil(t, tlsConn)
	if tlsConn != nil {
		assert.Nil(t, tlsConn.Close())
	}
}



func assertNotPanic(t *testing.T) {
	if r := recover(); r != nil {
		// Expect panic to be called with non nil error
		assert.True(t, false)
	} else {
		// This should never be called in case of a bug
		assert.True(t, true)
	}
}

func assertPanic(t *testing.T) {
	if r := recover(); r != nil {
		// Expect panic to be called with non nil error
		assert.True(t, true)
	} else {
		// This should never be called in case of a bug
		assert.True(t, false)
	}
}

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}

