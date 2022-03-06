// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

// Package rkzerointer provides common utility functions for middleware of go-zero framework
package rkzerointer

import (
	"bufio"
	"github.com/streadway/handy/atomic"
	"net"
	"net/http"
)

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
	if v, ok := w.Writer.(http.Hijacker); ok {
		return v.Hijack()
	}

	return nil, nil, nil
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
