// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.
package main

import (
	"fmt"
	"github.com/rookie-ninja/rk-entry/entry"
	rkzeroctx "github.com/rookie-ninja/rk-zero/interceptor/context"
	rkzerolog "github.com/rookie-ninja/rk-zero/interceptor/log/zap"
	rkzerotrace "github.com/rookie-ninja/rk-zero/interceptor/tracing/telemetry"
	"github.com/tal-tech/go-zero/rest"
	"github.com/tal-tech/go-zero/rest/httpx"
	"net/http"
)

// In this example, we will start a new go-zero server with tracing interceptor enabled.
// Listen on port of 8080 with GET /rk/v1/greeter?name=<xxx>.
func main() {
	// ****************************************
	// ********** Create Exporter *************
	// ****************************************

	// Export trace to stdout
	exporter := rkzerotrace.CreateFileExporter("stdout")

	// Export trace to local file system
	//exporter := rkzerotrace.CreateFileExporter("logs/trace.log")

	// Export trace to jaeger agent
	//exporter := rkzerotrace.CreateJaegerExporter(jaeger.WithAgentEndpoint())

	// ********************************************
	// ********** Enable interceptors *************
	// ********************************************
	interceptors := []rest.Middleware{
		rkzerolog.Interceptor(),
		rkzerotrace.Interceptor(
			// Entry name and entry type will be used for distinguishing interceptors. Recommended.
			//rkzerotrace.WithEntryNameAndType("greeter", "zero"),
			//
			// Provide an exporter.
			rkzerotrace.WithExporter(exporter),
			//
			// Provide propagation.TextMapPropagator
			// rkzerotrace.WithPropagator(<propagator>),
			//
			// Provide SpanProcessor
			// rkzerotrace.WithSpanProcessor(<span processor>),
			//
			// Provide TracerProvider
			// rkzerotrace.WithTracerProvider(<trace provider>),
		),
	}

	// 1: Create go-zero server
	server := startGreeterServer(interceptors...)
	defer server.Stop()

	// 2: Wait for ctrl-C to shutdown server
	rkentry.GlobalAppCtx.WaitForShutdownSig()
}

// Start go-zero server.
func startGreeterServer(interceptors ...rest.Middleware) *rest.Server {
	serverConf := rest.RestConf{
		Host: "0.0.0.0",
		Port: 8080,
	}
	serverConf.Name = "demo"
	// disable log
	serverConf.Log.Mode = "console"
	serverConf.Log.Level = "severe"

	server := rest.MustNewServer(serverConf)

	// register middleware
	for _, v := range interceptors {
		server.Use(v)
	}

	// register router
	server.AddRoute(rest.Route{
		Method:  http.MethodGet,
		Path:    "/rk/v1/greeter",
		Handler: Greeter,
	})

	go func() {
		server.Start()
	}()

	return server
}

// GreeterResponse Response of Greeter.
type GreeterResponse struct {
	Message string
}

// Greeter Handler.
func Greeter(writer http.ResponseWriter, req *http.Request) {
	rkzeroctx.GetLogger(req, writer).Info("Received request from client.")

	httpx.WriteJson(writer, http.StatusOK, &GreeterResponse{
		Message: fmt.Sprintf("Hello %s!", req.URL.Query().Get("name")),
	})
}
