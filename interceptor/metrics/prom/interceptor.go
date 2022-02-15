// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

// Package rkzerometrics is a middleware for go-zero framework which record prometheus metrics for RPC
package rkzerometrics

import (
	"context"
	rkmid "github.com/rookie-ninja/rk-entry/middleware"
	rkmidmetrics "github.com/rookie-ninja/rk-entry/middleware/metrics"
	"github.com/rookie-ninja/rk-zero/interceptor"
	"github.com/zeromicro/go-zero/rest"
	"net/http"
	"strconv"
)

// Interceptor create a new prometheus metrics interceptor with options.
func Interceptor(opts ...rkmidmetrics.Option) rest.Middleware {
	set := rkmidmetrics.NewOptionSet(opts...)

	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(writer http.ResponseWriter, req *http.Request) {
			// wrap writer
			writer = rkzerointer.WrapResponseWriter(writer)

			ctx := context.WithValue(req.Context(), rkmid.EntryNameKey, set.GetEntryName())
			req = req.WithContext(ctx)

			beforeCtx := set.BeforeCtx(req)
			set.Before(beforeCtx)

			next(writer, req)

			afterCtx := set.AfterCtx(strconv.Itoa(writer.(*rkzerointer.RkResponseWriter).Code))
			set.After(beforeCtx, afterCtx)
		}
	}
}
