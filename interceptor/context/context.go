// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

// Package rkzeroctx defines utility functions and variables used by go-zero middleware
package rkzeroctx

import (
	"context"
	"github.com/golang-jwt/jwt/v4"
	"github.com/rookie-ninja/rk-logger"
	"github.com/rookie-ninja/rk-query"
	"github.com/rookie-ninja/rk-zero/interceptor"
	otelcodes "go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"net/http"
)

const (
	// RequestIdKey is the header key sent to client
	RequestIdKey = "X-Request-Id"
	// TraceIdKey is the header sent to client
	TraceIdKey = "X-Trace-Id"
)

var (
	noopTracerProvider = trace.NewNoopTracerProvider()
	noopEvent          = rkquery.NewEventFactory().CreateEventNoop()
)

// GetIncomingHeaders extract call-scoped incoming headers
func GetIncomingHeaders(req *http.Request) http.Header {
	return req.Header
}

// AddHeaderToClient headers that would be sent to client.
// Values would be merged.
func AddHeaderToClient(w http.ResponseWriter, key, value string) {
	if w == nil {
		return
	}

	header := w.Header()
	header.Add(key, value)
}

// SetHeaderToClient headers that would be sent to client.
// Values would be overridden.
func SetHeaderToClient(w http.ResponseWriter, key, value string) {
	if w == nil {
		return
	}
	header := w.Header()
	header.Set(key, value)
}

// GetEvent extract takes the call-scoped EventData from middleware.
func GetEvent(req *http.Request) rkquery.Event {
	if req == nil {
		return noopEvent
	}

	if raw := req.Context().Value(rkzerointer.RpcEventKey); raw != nil {
		return raw.(rkquery.Event)
	}

	return noopEvent
}

// GetLogger extract takes the call-scoped zap logger from middleware.
func GetLogger(req *http.Request, w http.ResponseWriter) *zap.Logger {
	if req == nil {
		return rklogger.NoopLogger
	}

	if raw := req.Context().Value(rkzerointer.RpcLoggerKey); raw != nil {
		requestId := GetRequestId(w)
		traceId := GetTraceId(w)
		fields := make([]zap.Field, 0)
		if len(requestId) > 0 {
			fields = append(fields, zap.String("requestId", requestId))
		}
		if len(traceId) > 0 {
			fields = append(fields, zap.String("traceId", traceId))
		}

		return raw.(*zap.Logger).With(fields...)
	}

	return rklogger.NoopLogger
}

// GetRequestId extract request id from context.
// If user enabled meta interceptor, then a random request Id would e assigned and set to context as value.
// If user called AddHeaderToClient() with key of RequestIdKey, then a new request id would be updated.
func GetRequestId(w http.ResponseWriter) string {
	if w == nil {
		return ""
	}

	return w.Header().Get(RequestIdKey)
}

// GetTraceId extract trace id from context.
func GetTraceId(w http.ResponseWriter) string {
	if w == nil {
		return ""
	}

	return w.Header().Get(TraceIdKey)
}

// GetEntryName extract entry name from context.
func GetEntryName(req *http.Request) string {
	if req == nil {
		return ""
	}

	if raw := req.Context().Value(rkzerointer.RpcEntryNameKey); raw != nil {
		return raw.(string)
	}

	return ""
}

// GetTraceSpan extract the call-scoped span from context.
func GetTraceSpan(req *http.Request) trace.Span {
	_, span := noopTracerProvider.Tracer("rk-trace-noop").Start(context.TODO(), "noop-span")

	if req == nil {
		return span
	}

	_, span = noopTracerProvider.Tracer("rk-trace-noop").Start(req.Context(), "noop-span")

	if raw := req.Context().Value(rkzerointer.RpcSpanKey); raw != nil {
		return raw.(trace.Span)
	}

	return span
}

// GetTracer extract the call-scoped tracer from context.
func GetTracer(req *http.Request) trace.Tracer {
	if req == nil {
		return noopTracerProvider.Tracer("rk-trace-noop")
	}

	if raw := req.Context().Value(rkzerointer.RpcTracerKey); raw != nil {
		return raw.(trace.Tracer)
	}

	return noopTracerProvider.Tracer("rk-trace-noop")
}

// GetTracerProvider extract the call-scoped tracer provider from context.
func GetTracerProvider(req *http.Request) trace.TracerProvider {
	if req == nil {
		return noopTracerProvider
	}

	if raw := req.Context().Value(rkzerointer.RpcTracerProviderKey); raw != nil {
		return raw.(trace.TracerProvider)
	}

	return noopTracerProvider
}

// GetTracerPropagator extract takes the call-scoped propagator from middleware.
func GetTracerPropagator(req *http.Request) propagation.TextMapPropagator {
	if req == nil {
		return nil
	}

	if raw := req.Context().Value(rkzerointer.RpcPropagatorKey); raw != nil {
		return raw.(propagation.TextMapPropagator)
	}

	return nil
}

// InjectSpanToHttpRequest inject span to http request
func InjectSpanToHttpRequest(src *http.Request, dest *http.Request) {
	if src == nil || dest == nil {
		return
	}

	newCtx := trace.ContextWithRemoteSpanContext(src.Context(), GetTraceSpan(src).SpanContext())

	if propagator := GetTracerPropagator(src); propagator != nil {
		propagator.Inject(newCtx, propagation.HeaderCarrier(dest.Header))
	}
}

// NewTraceSpan start a new span
func NewTraceSpan(req *http.Request, name string) (*http.Request, trace.Span) {
	tracer := GetTracer(req)
	newCtx, span := tracer.Start(req.Context(), name)

	GetEvent(req).StartTimer(name)

	return req.WithContext(newCtx), span
}

// EndTraceSpan end span
func EndTraceSpan(span trace.Span, success bool) {
	if success {
		span.SetStatus(otelcodes.Ok, otelcodes.Ok.String())
	}

	span.End()
}

// GetJwtToken return jwt.Token if exists
func GetJwtToken(req *http.Request) *jwt.Token {
	if req == nil {
		return nil
	}

	if raw := req.Context().Value(rkzerointer.RpcJwtTokenKey); raw != nil {
		if res, ok := raw.(*jwt.Token); ok {
			return res
		}
	}

	return nil
}

// GetCsrfToken return csrf token if exists
func GetCsrfToken(req *http.Request) string {
	if req == nil {
		return ""
	}

	if raw := req.Context().Value(rkzerointer.RpcCsrfTokenKey); raw != nil {
		if res, ok := raw.(string); ok {
			return res
		}
	}

	return ""
}
