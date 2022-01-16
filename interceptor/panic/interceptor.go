// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

// Package rkzeropanic is a middleware of go-zero framework for recovering from panic
package rkzeropanic

import (
	"context"
	"github.com/rookie-ninja/rk-common/error"
	rkmid "github.com/rookie-ninja/rk-entry/middleware"
	rkmidpanic "github.com/rookie-ninja/rk-entry/middleware/panic"
	"github.com/rookie-ninja/rk-zero/interceptor"
	"github.com/rookie-ninja/rk-zero/interceptor/context"
	"github.com/tal-tech/go-zero/rest"
	"github.com/tal-tech/go-zero/rest/httpx"
	"net/http"
)

// Interceptor returns a rest.Middleware (middleware)
func Interceptor(opts ...rkmidpanic.Option) rest.Middleware {
	set := rkmidpanic.NewOptionSet(opts...)

	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(writer http.ResponseWriter, req *http.Request) {
			// wrap writer
			writer = rkzerointer.WrapResponseWriter(writer)

			ctx := context.WithValue(req.Context(), rkmid.EntryNameKey, set.GetEntryName())
			req = req.WithContext(ctx)

			handlerFunc := func(resp *rkerror.ErrorResp) {
				httpx.WriteJson(writer, resp.Err.Code, resp)
			}
			beforeCtx := set.BeforeCtx(rkzeroctx.GetEvent(req), rkzeroctx.GetLogger(req, writer), handlerFunc)
			set.Before(beforeCtx)

			defer beforeCtx.Output.DeferFunc()

			next(writer, req)
		}
	}
}
