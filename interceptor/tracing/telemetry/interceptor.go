// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

// Package rkzerotrace is aa middleware of go-zero framework for recording trace info of RPC
package rkzerotrace

import (
	"context"
	"github.com/rookie-ninja/rk-echo/interceptor"
	"github.com/rookie-ninja/rk-echo/interceptor/context"
	"github.com/rookie-ninja/rk-entry/entry"
	"github.com/rookie-ninja/rk-zero/interceptor"
	rkzeroctx "github.com/rookie-ninja/rk-zero/interceptor/context"
	"github.com/tal-tech/go-zero/rest"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	semconv "go.opentelemetry.io/otel/semconv/v1.4.0"
	oteltrace "go.opentelemetry.io/otel/trace"
	"net/http"
)

// Interceptor create a interceptor with opentelemetry.
func Interceptor(opts ...Option) rest.Middleware {
	set := newOptionSet(opts...)

	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(writer http.ResponseWriter, req *http.Request) {
			// wrap writer
			writer = rkzerointer.WrapResponseWriter(writer)

			req = req.WithContext(context.WithValue(req.Context(), rkzerointer.RpcEntryNameKey, set.EntryName))
			req = req.WithContext(context.WithValue(req.Context(), rkzerointer.RpcTracerKey, set.Tracer))
			req = req.WithContext(context.WithValue(req.Context(), rkzerointer.RpcTracerProviderKey, set.Provider))
			req = req.WithContext(context.WithValue(req.Context(), rkzerointer.RpcPropagatorKey, set.Propagator))

			span, newReq := before(req, writer, set)
			defer span.End()

			next(writer, newReq)

			after(writer.(*rkzerointer.RkResponseWriter), span)
		}
	}
}

func before(req *http.Request, writer http.ResponseWriter, set *optionSet) (oteltrace.Span, *http.Request) {
	opts := []oteltrace.SpanStartOption{
		oteltrace.WithAttributes(semconv.NetAttributesFromHTTPRequest("tcp", req)...),
		oteltrace.WithAttributes(semconv.EndUserAttributesFromHTTPRequest(req)...),
		oteltrace.WithAttributes(semconv.HTTPServerAttributesFromHTTPRequest(rkentry.GlobalAppCtx.GetAppInfoEntry().AppName, req.URL.Path, req)...),
		oteltrace.WithAttributes(localeToAttributes()...),
		oteltrace.WithSpanKind(oteltrace.SpanKindServer),
	}

	// 1: extract tracing info from request header
	spanCtx := oteltrace.SpanContextFromContext(
		set.Propagator.Extract(req.Context(), propagation.HeaderCarrier(req.Header)))

	spanName := req.URL.Path
	if len(spanName) < 1 {
		spanName = "rk-span-default"
	}

	// 2: start new span
	newRequestCtx, span := set.Tracer.Start(
		oteltrace.ContextWithRemoteSpanContext(req.Context(), spanCtx),
		spanName, opts...)
	// 2.1: pass the span through the request context
	req = req.WithContext(newRequestCtx)

	// 3: read trace id, tracer, traceProvider, propagator and logger into event data and echo context
	rkzeroctx.GetEvent(req).SetTraceId(span.SpanContext().TraceID().String())
	writer.Header().Set(rkechoctx.TraceIdKey, span.SpanContext().TraceID().String())

	req = req.WithContext(context.WithValue(req.Context(), rkzerointer.RpcSpanKey, span))
	return span, req
}

func after(writer *rkzerointer.RkResponseWriter, span oteltrace.Span) {
	attrs := semconv.HTTPAttributesFromHTTPStatusCode(writer.Code)
	spanStatus, spanMessage := semconv.SpanStatusFromHTTPStatusCode(writer.Code)
	span.SetAttributes(attrs...)
	span.SetStatus(spanStatus, spanMessage)
}

// Convert locale information into attributes.
func localeToAttributes() []attribute.KeyValue {
	res := []attribute.KeyValue{
		attribute.String(rkechointer.Realm.Key, rkechointer.Realm.String),
		attribute.String(rkechointer.Region.Key, rkechointer.Region.String),
		attribute.String(rkechointer.AZ.Key, rkechointer.AZ.String),
		attribute.String(rkechointer.Domain.Key, rkechointer.Domain.String),
	}

	return res
}
