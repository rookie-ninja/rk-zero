// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

// Package rkzeroauth is auth middleware for go-zero framework
package rkzeroauth

import (
	"context"
	"github.com/rookie-ninja/rk-entry/v2/middleware"
	"github.com/rookie-ninja/rk-entry/v2/middleware/auth"
	"github.com/rookie-ninja/rk-zero/middleware"
	"github.com/zeromicro/go-zero/rest"
	"github.com/zeromicro/go-zero/rest/httpx"
	"net/http"
)

// Middleware validate bellow authorization.
//
// 1: Basic Auth: The client sends HTTP requests with the Authorization header that contains the word Basic, followed by a space and a base64-encoded(non-encrypted) string username: password.
// 2: Bearer Token: Commonly known as token authentication. It is an HTTP authentication scheme that involves security tokens called bearer tokens.
// 3: API key: An API key is a token that a client provides when making API calls. With API key auth, you send a key-value pair to the API in the request headers.
func Middleware(opts ...rkmidauth.Option) rest.Middleware {
	set := rkmidauth.NewOptionSet(opts...)

	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(writer http.ResponseWriter, req *http.Request) {
			// wrap writer
			writer = rkzerointer.WrapResponseWriter(writer)

			ctx := context.WithValue(req.Context(), rkmid.EntryNameKey, set.GetEntryName())
			req = req.WithContext(ctx)

			// case 1: return to user if error occur
			beforeCtx := set.BeforeCtx(req)
			set.Before(beforeCtx)

			if beforeCtx.Output.ErrResp != nil {
				for k, v := range beforeCtx.Output.HeadersToReturn {
					writer.Header().Set(k, v)
				}
				httpx.WriteJson(writer, beforeCtx.Output.ErrResp.Code(), beforeCtx.Output.ErrResp)
				return
			}

			next(writer, req)
		}
	}
}
