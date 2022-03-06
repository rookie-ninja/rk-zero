// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

// Package rkzerotrace is aa middleware of go-zero framework for recording trace info of RPC
package rkzerotrace

import (
	"context"
	"github.com/rookie-ninja/rk-entry/v2/middleware"
	"github.com/rookie-ninja/rk-entry/v2/middleware/tracing"
	"github.com/rookie-ninja/rk-zero/middleware"
	"github.com/rookie-ninja/rk-zero/middleware/context"
	"github.com/zeromicro/go-zero/rest"
	"go.opentelemetry.io/otel"
	"net/http"
)

// Middleware create a interceptor with opentelemetry.
func Middleware(opts ...rkmidtrace.Option) rest.Middleware {
	set := rkmidtrace.NewOptionSet(opts...)

	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(writer http.ResponseWriter, req *http.Request) {
			// wrap writer
			writer = rkzerointer.WrapResponseWriter(writer)

			ctx := context.WithValue(req.Context(), rkmid.EntryNameKey, set.GetEntryName())
			req = req.WithContext(ctx)

			ctx = context.WithValue(req.Context(), rkmid.TracerKey, set.GetTracer())
			req = req.WithContext(ctx)

			ctx = context.WithValue(req.Context(), rkmid.TracerProviderKey, set.GetProvider())
			req = req.WithContext(ctx)

			ctx = context.WithValue(req.Context(), rkmid.PropagatorKey, set.GetPropagator())
			req = req.WithContext(ctx)

			// go-zero从全局对象读数据，需要将Provider、Propagator等信息更新到全局对象
			// https://github.com/zeromicro/go-zero/blob/a91c3907a8f68b6f08b1bad0125d7d5016105032/rest/handler/tracinghandler.go#L16
			otel.SetTracerProvider(set.GetProvider())
			otel.SetTextMapPropagator(set.GetPropagator())

			beforeCtx := set.BeforeCtx(req, false)
			set.Before(beforeCtx)

			// create request with new context
			req = req.WithContext(beforeCtx.Output.NewCtx)

			// add to context
			if beforeCtx.Output.Span != nil {
				traceId := beforeCtx.Output.Span.SpanContext().TraceID().String()
				rkzeroctx.GetEvent(req).SetTraceId(traceId)
				writer.Header().Set(rkmid.HeaderTraceId, traceId)
				ctx = context.WithValue(req.Context(), rkmid.SpanKey, beforeCtx.Output.Span)
				req = req.WithContext(ctx)
			}

			next(writer, req)

			afterCtx := set.AfterCtx(writer.(*rkzerointer.RkResponseWriter).Code, "")
			set.After(beforeCtx, afterCtx)
		}
	}
}
