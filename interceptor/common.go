// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

// Package rkzerointer provides common utility functions for middleware of go-zero framework
package rkzerointer

import (
	"bufio"
	"github.com/rookie-ninja/rk-common/common"
	"github.com/streadway/handy/atomic"
	"go.uber.org/zap"
	"net"
	"net/http"
	"strings"
)

var (
	// Realm environment variable
	Realm = zap.String("realm", rkcommon.GetEnvValueOrDefault("REALM", "*"))
	// Region environment variable
	Region = zap.String("region", rkcommon.GetEnvValueOrDefault("REGION", "*"))
	// AZ environment variable
	AZ = zap.String("az", rkcommon.GetEnvValueOrDefault("AZ", "*"))
	// Domain environment variable
	Domain = zap.String("domain", rkcommon.GetEnvValueOrDefault("DOMAIN", "*"))
	// LocalIp read local IP from localhost
	LocalIp = zap.String("localIp", rkcommon.GetLocalIP())
	// LocalHostname read hostname from localhost
	LocalHostname = zap.String("localHostname", rkcommon.GetLocalHostname())
)

const (
	// RpcEntryNameKey entry name key
	RpcEntryNameKey = "zeroEntryName"
	// RpcEntryNameValue entry name
	RpcEntryNameValue = "zero"
	// RpcEntryTypeValue entry type
	RpcEntryTypeValue = "zero"
	// RpcEventKey event key
	RpcEventKey = "zeroEvent"
	// RpcLoggerKey logger key
	RpcLoggerKey = "zeroLogger"
	// RpcTracerKey tracer key
	RpcTracerKey = "zeroTracer"
	// RpcSpanKey span key
	RpcSpanKey = "zeroSpan"
	// RpcTracerProviderKey trace provider key
	RpcTracerProviderKey = "zeroTracerProvider"
	// RpcPropagatorKey propagator key
	RpcPropagatorKey = "zeroPropagator"
	// RpcAuthorizationHeaderKey auth key
	RpcAuthorizationHeaderKey = "authorization"
	// RpcApiKeyHeaderKey api auth key
	RpcApiKeyHeaderKey = "X-API-Key"
	// RpcJwtTokenKey key of jwt token in context
	RpcJwtTokenKey = "zeroJwt"
	// RpcCsrfTokenKey key of csrf token injected by csrf middleware
	RpcCsrfTokenKey = "zeroCsrfToken"
)

// GetRemoteAddressSet returns remote endpoint information set including IP, Port.
// We will do as best as we can to determine it.
// If fails, then just return default ones.
func GetRemoteAddressSet(req *http.Request) (remoteIp, remotePort string) {
	remoteIp, remotePort = "0.0.0.0", "0"

	if req == nil {
		return
	}

	var err error
	if remoteIp, remotePort, err = net.SplitHostPort(req.RemoteAddr); err != nil {
		return
	}

	forwardedRemoteIp := req.Header.Get("x-forwarded-for")

	// Deal with forwarded remote ip
	if len(forwardedRemoteIp) > 0 {
		if forwardedRemoteIp == "::1" {
			forwardedRemoteIp = "localhost"
		}

		remoteIp = forwardedRemoteIp
	}

	if remoteIp == "::1" {
		remoteIp = "localhost"
	}

	return remoteIp, remotePort
}

// ShouldLog determines whether should log the RPC
func ShouldLog(req *http.Request) bool {
	if req == nil {
		return false
	}

	// ignoring /rk/v1/assets, /rk/v1/tv and /sw/ path while logging since these are internal APIs.
	if strings.HasPrefix(req.URL.Path, "/rk/v1/assets") ||
		strings.HasPrefix(req.URL.Path, "/rk/v1/tv") ||
		strings.HasPrefix(req.URL.Path, "/sw/") {
		return false
	}

	return true
}

// WrapResponseWriter if current writer is not RkResponseWriter
func WrapResponseWriter(w http.ResponseWriter) *RkResponseWriter {
	switch v := w.(type) {
	case *RkResponseWriter:
		return v
	}

	return &RkResponseWriter{
		Writer: w,
		Code:   http.StatusOK,
		Size:   atomic.Int(0),
	}
}

// A RkResponseWriter is a helper to delay sealing a http.ResponseWriter on writing code.
type RkResponseWriter struct {
	Writer http.ResponseWriter
	Code   int
	Size   atomic.Int
}

// Flush flushes the response writer.
func (w *RkResponseWriter) Flush() {
	if flusher, ok := w.Writer.(http.Flusher); ok {
		flusher.Flush()
	}
}

// Header returns the http header.
func (w *RkResponseWriter) Header() http.Header {
	return w.Writer.Header()
}

// Hijack implements the http.Hijacker interface.
// This expands the Response to fulfill http.Hijacker if the underlying http.ResponseWriter supports it.
func (w *RkResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.Writer.(http.Hijacker).Hijack()
}

// Write writes bytes into w.
func (w *RkResponseWriter) Write(bytes []byte) (int, error) {
	len, err := w.Writer.Write(bytes)
	w.Size.Add(int64(len))
	return len, err
}

// WriteHeader writes code into w, and not sealing the writer.
func (w *RkResponseWriter) WriteHeader(code int) {
	w.Writer.WriteHeader(code)
	w.Code = code
}
