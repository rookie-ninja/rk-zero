// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

// Package rkzerolog is a middleware for go-zero framework for logging RPC.
package rkzerolog

import (
	"context"
	"github.com/rookie-ninja/rk-entry/v2/middleware"
	"github.com/rookie-ninja/rk-entry/v2/middleware/log"
	"github.com/rookie-ninja/rk-zero/middleware"
	"github.com/rookie-ninja/rk-zero/middleware/context"
	"github.com/zeromicro/go-zero/rest"
	"net/http"
	"strconv"
)

// Middleware returns a rest.Middleware (middleware) that logs requests using uber-go/zap.
func Middleware(opts ...rkmidlog.Option) rest.Middleware {
	set := rkmidlog.NewOptionSet(opts...)

	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(writer http.ResponseWriter, req *http.Request) {
			// wrap writer
			writer = rkzerointer.WrapResponseWriter(writer)

			ctx := context.WithValue(req.Context(), rkmid.EntryNameKey, set.GetEntryName())
			req = req.WithContext(ctx)

			// call before
			beforeCtx := set.BeforeCtx(req)
			set.Before(beforeCtx)

			ctx = context.WithValue(req.Context(), rkmid.EventKey, beforeCtx.Output.Event)
			req = req.WithContext(ctx)

			ctx = context.WithValue(req.Context(), rkmid.LoggerKey, beforeCtx.Output.Logger)
			req = req.WithContext(ctx)

			next(writer, req)

			// call after
			afterCtx := set.AfterCtx(
				rkzeroctx.GetRequestId(writer),
				rkzeroctx.GetTraceId(writer),
				strconv.Itoa(writer.(*rkzerointer.RkResponseWriter).Code))
			set.After(beforeCtx, afterCtx)
		}
	}
}
