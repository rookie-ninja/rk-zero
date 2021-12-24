// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

// Package rkzerometrics is a middleware for go-zero framework which record prometheus metrics for RPC
package rkzerometrics

import (
	"context"
	"github.com/rookie-ninja/rk-zero/interceptor"
	"github.com/tal-tech/go-zero/rest"
	"net/http"
	"time"
)

// Interceptor create a new prometheus metrics interceptor with options.
func Interceptor(opts ...Option) rest.Middleware {
	set := newOptionSet(opts...)

	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(writer http.ResponseWriter, req *http.Request) {
			// wrap writer
			writer = rkzerointer.WrapResponseWriter(writer)

			req = req.WithContext(context.WithValue(req.Context(), rkzerointer.RpcEntryNameKey, set.EntryName))

			// start timer
			startTime := time.Now()

			next(writer, req)

			// end timer
			elapsed := time.Now().Sub(startTime)

			// ignoring /rk/v1/assets, /rk/v1/tv and /sw/ path while logging since these are internal APIs.
			if rkzerointer.ShouldLog(req) {
				if durationMetrics := GetServerDurationMetrics(req, writer); durationMetrics != nil {
					durationMetrics.Observe(float64(elapsed.Nanoseconds()))
				}

				if resCodeMetrics := GetServerResCodeMetrics(req, writer); resCodeMetrics != nil {
					resCodeMetrics.Inc()
				}
			}
		}
	}
}
