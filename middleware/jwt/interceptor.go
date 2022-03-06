// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

// Package rkzerojwt is a middleware for go-zero framework which validating jwt token for RPC
package rkzerojwt

import (
	"context"
	"github.com/rookie-ninja/rk-entry/v2/middleware"
	"github.com/rookie-ninja/rk-entry/v2/middleware/jwt"
	"github.com/rookie-ninja/rk-zero/middleware"
	"github.com/zeromicro/go-zero/rest"
	"github.com/zeromicro/go-zero/rest/httpx"
	"net/http"
)

// Middleware Add jwt interceptors.
//
// Mainly copied from bellow.
// https://github.com/labstack/echo/blob/master/middleware/jwt.go
func Middleware(opts ...rkmidjwt.Option) rest.Middleware {
	set := rkmidjwt.NewOptionSet(opts...)

	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(writer http.ResponseWriter, req *http.Request) {
			// wrap writer
			writer = rkzerointer.WrapResponseWriter(writer)

			ctx := context.WithValue(req.Context(), rkmid.EntryNameKey, set.GetEntryName())
			req = req.WithContext(ctx)

			beforeCtx := set.BeforeCtx(req, nil)
			set.Before(beforeCtx)

			// case 1: error response
			if beforeCtx.Output.ErrResp != nil {
				httpx.WriteJson(writer, beforeCtx.Output.ErrResp.Err.Code, beforeCtx.Output.ErrResp)
				return
			}

			// insert into context
			ctx = context.WithValue(req.Context(), rkmid.JwtTokenKey, beforeCtx.Output.JwtToken)
			req = req.WithContext(ctx)

			next(writer, req)
		}
	}
}
