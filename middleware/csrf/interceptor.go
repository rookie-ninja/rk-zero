// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

// Package rkzerocsrf is a middleware for go-zero framework which validating csrf token for RPC
package rkzerocsrf

import (
	"context"
	"github.com/rookie-ninja/rk-entry/v2/middleware"
	"github.com/rookie-ninja/rk-entry/v2/middleware/csrf"
	"github.com/rookie-ninja/rk-zero/middleware"
	"github.com/zeromicro/go-zero/rest"
	"github.com/zeromicro/go-zero/rest/httpx"
	"net/http"
)

// Middleware Add csrf interceptors.
//
// Mainly copied from bellow.
// https://github.com/labstack/echo/blob/master/middleware/csrf.go
func Middleware(opts ...rkmidcsrf.Option) rest.Middleware {
	set := rkmidcsrf.NewOptionSet(opts...)

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

			for _, v := range beforeCtx.Output.VaryHeaders {
				writer.Header().Add(rkmid.HeaderVary, v)
			}

			if beforeCtx.Output.Cookie != nil {
				http.SetCookie(writer, beforeCtx.Output.Cookie)
			}

			// store token in the context
			ctx = context.WithValue(req.Context(), rkmid.CsrfTokenKey, beforeCtx.Input.Token)
			req = req.WithContext(ctx)

			next(writer, req)
		}
	}
}
