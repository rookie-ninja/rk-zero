// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

// Package rkzeropanic is a middleware of go-zero framework for recovering from panic
package rkzeropanic

import (
	"context"
	"fmt"
	"github.com/rookie-ninja/rk-common/error"
	"github.com/rookie-ninja/rk-zero/interceptor"
	"github.com/rookie-ninja/rk-zero/interceptor/context"
	"github.com/tal-tech/go-zero/rest"
	"github.com/tal-tech/go-zero/rest/httpx"
	"go.uber.org/zap"
	"net/http"
	"runtime/debug"
)

// Interceptor returns a rest.Middleware (middleware)
func Interceptor(opts ...Option) rest.Middleware {
	set := newOptionSet(opts...)

	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(writer http.ResponseWriter, req *http.Request) {
			// wrap writer
			writer = rkzerointer.WrapResponseWriter(writer)

			req = req.WithContext(context.WithValue(req.Context(), rkzerointer.RpcEntryNameKey, set.EntryName))

			defer func() {
				if recv := recover(); recv != nil {
					var res *rkerror.ErrorResp

					if se, ok := recv.(*rkerror.ErrorResp); ok {
						res = se
					} else if re, ok := recv.(error); ok {
						res = rkerror.FromError(re)
					} else {
						res = rkerror.New(rkerror.WithMessage(fmt.Sprintf("%v", recv)))
					}

					rkzeroctx.GetEvent(req).SetCounter("panic", 1)
					rkzeroctx.GetEvent(req).AddErr(res.Err)
					rkzeroctx.GetLogger(req, writer).Error(fmt.Sprintf("panic occurs:\n%s", string(debug.Stack())), zap.Error(res.Err))

					httpx.WriteJson(writer, http.StatusInternalServerError, res)
				}
			}()

			next(writer, req)
		}
	}
}
