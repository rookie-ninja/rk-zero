// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

// Package rkzerosec is a middleware of go-zero framework for adding secure headers in RPC response
package rkzerosec

import (
	"context"
	"github.com/rookie-ninja/rk-entry/v2/middleware"
	"github.com/rookie-ninja/rk-entry/v2/middleware/secure"
	"github.com/rookie-ninja/rk-zero/v2/middleware"
	"github.com/zeromicro/go-zero/rest"
	"net/http"
)

// Middleware Add security interceptors.
//
// Mainly copied from bellow.
// https://github.com/labstack/echo/blob/master/middleware/secure.go
func Middleware(opts ...rkmidsec.Option) rest.Middleware {
	set := rkmidsec.NewOptionSet(opts...)

	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(writer http.ResponseWriter, req *http.Request) {
			// wrap writer
			writer = rkzerointer.WrapResponseWriter(writer)

			ctx := context.WithValue(req.Context(), rkmid.EntryNameKey, set.GetEntryName())
			req = req.WithContext(ctx)

			// case 1: return to user if error occur
			beforeCtx := set.BeforeCtx(req)
			set.Before(beforeCtx)

			for k, v := range beforeCtx.Output.HeadersToReturn {
				writer.Header().Set(k, v)
			}

			next(writer, req)
		}
	}
}
