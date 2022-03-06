// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

// Package rkzerometa is a middleware of go-zero framework for adding metadata in RPC response
package rkzerometa

import (
	"context"
	"github.com/rookie-ninja/rk-entry/v2/middleware"
	"github.com/rookie-ninja/rk-entry/v2/middleware/meta"
	"github.com/rookie-ninja/rk-zero/middleware"
	"github.com/rookie-ninja/rk-zero/middleware/context"
	"github.com/zeromicro/go-zero/rest"
	"net/http"
)

// Interceptor will add common headers as extension style in http response.
func Middleware(opts ...rkmidmeta.Option) rest.Middleware {
	set := rkmidmeta.NewOptionSet(opts...)

	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(writer http.ResponseWriter, req *http.Request) {
			// wrap writer
			writer = rkzerointer.WrapResponseWriter(writer)

			ctx := context.WithValue(req.Context(), rkmid.EntryNameKey, set.GetEntryName())
			req = req.WithContext(ctx)

			beforeCtx := set.BeforeCtx(req, rkzeroctx.GetEvent(req))
			set.Before(beforeCtx)

			ctx = context.WithValue(req.Context(), rkmid.HeaderRequestId, beforeCtx.Output.RequestId)
			req = req.WithContext(ctx)

			for k, v := range beforeCtx.Output.HeadersToReturn {
				writer.Header().Set(k, v)
			}

			next(writer, req)
		}
	}
}
