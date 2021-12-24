// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

// Package rkzerojwt is a middleware for go-zero framework which validating jwt token for RPC
package rkzerojwt

import (
	"context"
	"github.com/rookie-ninja/rk-common/error"
	"github.com/rookie-ninja/rk-zero/interceptor"
	"github.com/tal-tech/go-zero/rest"
	"github.com/tal-tech/go-zero/rest/httpx"
	"net/http"
)

// Interceptor Add jwt interceptors.
//
// Mainly copied from bellow.
// https://github.com/labstack/echo/blob/master/middleware/jwt.go
func Interceptor(opts ...Option) rest.Middleware {
	set := newOptionSet(opts...)

	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(writer http.ResponseWriter, req *http.Request) {
			// wrap writer
			writer = rkzerointer.WrapResponseWriter(writer)

			ctx := context.WithValue(req.Context(), rkzerointer.RpcEntryNameKey, set.EntryName)
			req = req.WithContext(ctx)

			if set.Skipper(req) {
				next(writer, req)
				return
			}

			// extract token from extractor
			var auth string
			var err error
			for _, extractor := range set.extractors {
				// Extract token from extractor, if it's not fail break the loop and
				// set auth
				auth, err = extractor(req)
				if err == nil {
					break
				}
			}

			if err != nil {
				httpx.WriteJson(writer, http.StatusUnauthorized, rkerror.New(
					rkerror.WithHttpCode(http.StatusUnauthorized),
					rkerror.WithMessage("invalid or expired jwt"),
					rkerror.WithDetails(err)))
				return
			}

			// parse token
			token, err := set.ParseTokenFunc(auth, req)

			if err != nil {
				httpx.WriteJson(writer, http.StatusUnauthorized, rkerror.New(
					rkerror.WithHttpCode(http.StatusUnauthorized),
					rkerror.WithMessage("invalid or expired jwt"),
					rkerror.WithDetails(err)))
				return
			}

			// insert into context
			req = req.WithContext(context.WithValue(req.Context(), rkzerointer.RpcJwtTokenKey, token))

			next(writer, req)
		}
	}
}
