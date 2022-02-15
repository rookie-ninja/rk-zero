// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

// Package rkzerocors is a CORS middleware for go-zero framework
package rkzerocors

import (
	"context"
	rkmid "github.com/rookie-ninja/rk-entry/middleware"
	rkmidcors "github.com/rookie-ninja/rk-entry/middleware/cors"
	"github.com/rookie-ninja/rk-zero/interceptor"
	"github.com/zeromicro/go-zero/rest"
	"net/http"
)

// Interceptor Add cors interceptors.
//
// Mainly copied and modified from bellow.
// https://github.com/labstack/echo/blob/master/middleware/cors.go
func Interceptor(opts ...rkmidcors.Option) rest.Middleware {
	set := rkmidcors.NewOptionSet(opts...)

	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(writer http.ResponseWriter, req *http.Request) {
			// wrap writer
			writer = rkzerointer.WrapResponseWriter(writer)

			ctx := context.WithValue(req.Context(), rkmid.EntryNameKey, set.GetEntryName())
			req = req.WithContext(ctx)

			beforeCtx := set.BeforeCtx(req)
			set.Before(beforeCtx)

			for k, v := range beforeCtx.Output.HeadersToReturn {
				writer.Header().Set(k, v)
			}

			for _, v := range beforeCtx.Output.HeaderVary {
				writer.Header().Add(rkmid.HeaderVary, v)
			}

			// case 1: with abort
			if beforeCtx.Output.Abort {
				writer.WriteHeader(http.StatusNoContent)
				return
			}

			next(writer, req)
		}
	}
}
