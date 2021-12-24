// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

// Package rkzerotimeout is a middleware of go-zero framework for timing out request in RPC response
package rkzerotimeout

import (
	"context"
	"github.com/rookie-ninja/rk-zero/interceptor"
	"github.com/tal-tech/go-zero/rest"
	"net/http"
)

// Interceptor Add timeout interceptors.
func Interceptor(opts ...Option) rest.Middleware {
	set := newOptionSet(opts...)

	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(writer http.ResponseWriter, req *http.Request) {
			// wrap writer
			writer = rkzerointer.WrapResponseWriter(writer)

			req = req.WithContext(context.WithValue(req.Context(), rkzerointer.RpcEntryNameKey, set.EntryName))

			set.Tick(req, writer, next)
		}
	}
}
