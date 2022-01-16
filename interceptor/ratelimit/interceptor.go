// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

// Package rkzerolimit is a middleware of go-zero framework for adding rate limit in RPC response
package rkzerolimit

import (
	"context"
	rkmid "github.com/rookie-ninja/rk-entry/middleware"
	rkmidlimit "github.com/rookie-ninja/rk-entry/middleware/ratelimit"
	"github.com/rookie-ninja/rk-zero/interceptor"
	"github.com/tal-tech/go-zero/rest"
	"github.com/tal-tech/go-zero/rest/httpx"
	"net/http"
)

// Interceptor Add rate limit interceptors.
func Interceptor(opts ...rkmidlimit.Option) rest.Middleware {
	set := rkmidlimit.NewOptionSet(opts...)

	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(writer http.ResponseWriter, req *http.Request) {
			// wrap writer
			writer = rkzerointer.WrapResponseWriter(writer)

			ctx := context.WithValue(req.Context(), rkmid.EntryNameKey, set.GetEntryName())
			req = req.WithContext(ctx)

			beforeCtx := set.BeforeCtx(req)
			set.Before(beforeCtx)

			if beforeCtx.Output.ErrResp != nil {
				httpx.WriteJson(writer, beforeCtx.Output.ErrResp.Err.Code, beforeCtx.Output.ErrResp)
				return
			}

			next(writer, req)
		}
	}
}
