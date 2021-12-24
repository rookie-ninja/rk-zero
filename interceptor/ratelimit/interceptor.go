// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

// Package rkzerolimit is a middleware of go-zero framework for adding rate limit in RPC response
package rkzerolimit

import (
	"context"
	"github.com/rookie-ninja/rk-common/error"
	"github.com/rookie-ninja/rk-zero/interceptor"
	"github.com/rookie-ninja/rk-zero/interceptor/context"
	"github.com/tal-tech/go-zero/rest"
	"github.com/tal-tech/go-zero/rest/httpx"
	"net/http"
)

// Interceptor Add rate limit interceptors.
func Interceptor(opts ...Option) rest.Middleware {
	set := newOptionSet(opts...)

	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(writer http.ResponseWriter, req *http.Request) {
			// wrap writer
			writer = rkzerointer.WrapResponseWriter(writer)

			req = req.WithContext(context.WithValue(req.Context(), rkzerointer.RpcEntryNameKey, set.EntryName))

			event := rkzeroctx.GetEvent(req)

			if duration, err := set.Wait(req); err != nil {
				event.SetCounter("rateLimitWaitMs", duration.Milliseconds())
				event.AddErr(err)

				httpx.WriteJson(writer, http.StatusTooManyRequests, rkerror.New(
					rkerror.WithHttpCode(http.StatusTooManyRequests),
					rkerror.WithDetails(err)))
				return
			}

			next(writer, req)
		}
	}
}
