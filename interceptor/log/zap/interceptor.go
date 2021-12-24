// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

// Package rkzerolog is a middleware for go-zero framework for logging RPC.
package rkzerolog

import (
	"context"
	"github.com/rookie-ninja/rk-entry/entry"
	"github.com/rookie-ninja/rk-query"
	"github.com/rookie-ninja/rk-zero/interceptor"
	"github.com/rookie-ninja/rk-zero/interceptor/context"
	"github.com/tal-tech/go-zero/rest"
	"go.uber.org/zap"
	"net/http"
	"strconv"
	"time"
)

// Interceptor returns a gin.HandlerFunc (middleware) that logs requests using uber-go/zap.
func Interceptor(opts ...Option) rest.Middleware {
	set := newOptionSet(opts...)

	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(writer http.ResponseWriter, req *http.Request) {
			// wrap writer
			writer = rkzerointer.WrapResponseWriter(writer)

			req = req.WithContext(context.WithValue(req.Context(), rkzerointer.RpcEntryNameKey, set.EntryName))

			req = before(req, set)

			next(writer, req)

			after(req, writer, set)
		}
	}
}

func before(req *http.Request, set *optionSet) *http.Request {
	var event rkquery.Event
	if rkzerointer.ShouldLog(req) {
		event = set.eventLoggerEntry.GetEventFactory().CreateEvent(
			rkquery.WithZapLogger(set.eventLoggerOverride),
			rkquery.WithEncoding(set.eventLoggerEncoding),
			rkquery.WithAppName(rkentry.GlobalAppCtx.GetAppInfoEntry().AppName),
			rkquery.WithAppVersion(rkentry.GlobalAppCtx.GetAppInfoEntry().Version),
			rkquery.WithEntryName(set.EntryName),
			rkquery.WithEntryType(set.EntryType))
	} else {
		event = set.eventLoggerEntry.GetEventFactory().CreateEventNoop()
	}

	event.SetStartTime(time.Now())

	remoteIp, remotePort := rkzerointer.GetRemoteAddressSet(req)
	// handle remote address
	event.SetRemoteAddr(remoteIp + ":" + remotePort)

	payloads := []zap.Field{
		zap.String("apiPath", req.URL.Path),
		zap.String("apiMethod", req.Method),
		zap.String("apiQuery", req.URL.RawQuery),
		zap.String("apiProtocol", req.Proto),
		zap.String("userAgent", req.UserAgent()),
	}

	// handle payloads
	event.AddPayloads(payloads...)

	// handle operation
	event.SetOperation(req.URL.Path)

	req = req.WithContext(context.WithValue(req.Context(), rkzerointer.RpcEventKey, event))
	req = req.WithContext(context.WithValue(req.Context(), rkzerointer.RpcLoggerKey, set.ZapLogger))

	return req
}

func after(req *http.Request, writer http.ResponseWriter, set *optionSet) {
	event := rkzeroctx.GetEvent(req)

	if requestId := rkzeroctx.GetRequestId(writer); len(requestId) > 0 {
		event.SetEventId(requestId)
		event.SetRequestId(requestId)
	}

	if traceId := rkzeroctx.GetTraceId(writer); len(traceId) > 0 {
		event.SetTraceId(traceId)
	}

	// writer must be RkResponseWriter
	event.SetResCode(strconv.Itoa(writer.(*rkzerointer.RkResponseWriter).Code))
	event.SetEndTime(time.Now())
	event.Finish()
}
