// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.
package main

import (
	"fmt"
	"github.com/rookie-ninja/rk-entry/entry"
	"github.com/rookie-ninja/rk-zero/interceptor/auth"
	"github.com/rookie-ninja/rk-zero/interceptor/context"
	"github.com/rookie-ninja/rk-zero/interceptor/log/zap"
	"github.com/tal-tech/go-zero/rest"
	"github.com/tal-tech/go-zero/rest/httpx"
	"net/http"
)

// In this example, we will start a new go-zero server with auth interceptor enabled.
// Listen on port of 8080 with GET /rk/v1/greeter?name=<xxx>.
func main() {
	// ********************************************
	// ********** Enable interceptors *************
	// ********************************************
	interceptors := []rest.Middleware{
		rkzerolog.Interceptor(),
		rkzeroauth.Interceptor(
			// rkzeroauth.WithIgnorePrefix("/rk/v1/greeter"),
			rkzeroauth.WithBasicAuth("", "rk-user:rk-pass"),
			rkzeroauth.WithApiKeyAuth("rk-api-key"),
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
	validateCtx(writer, req)

	httpx.WriteJson(writer, http.StatusOK, &GreeterResponse{
		Message: fmt.Sprintf("Hello %s!", req.URL.Query().Get("name")),
	})
}

func validateCtx(writer http.ResponseWriter, req *http.Request) {
	// 1: get incoming headers
	printIndex("[1]: get incoming headers")
	prettyHeader(rkzeroctx.GetIncomingHeaders(req))

	// 2: add header to client
	printIndex("[2]: add header to client")
	rkzeroctx.AddHeaderToClient(writer, "add-key", "add-value")

	// 3: set header to client
	printIndex("[3]: set header to client")
	rkzeroctx.SetHeaderToClient(writer, "set-key", "set-value")

	// 4: get event
	printIndex("[4]: get event")
	rkzeroctx.GetEvent(req).SetCounter("my-counter", 1)

	// 5: get logger
	printIndex("[5]: get logger")
	rkzeroctx.GetLogger(req, writer).Info("error msg")

	// 6: get request id
	printIndex("[6]: get request id")
	fmt.Println(rkzeroctx.GetRequestId(writer))

	// 7: get trace id
	printIndex("[7]: get trace id")
	fmt.Println(rkzeroctx.GetTraceId(writer))

	// 8: get entry name
	printIndex("[8]: get entry name")
	fmt.Println(rkzeroctx.GetEntryName(req))

	// 9: get trace span
	printIndex("[9]: get trace span")
	fmt.Println(rkzeroctx.GetTraceSpan(req))

	// 10: get tracer
	printIndex("[10]: get tracer")
	fmt.Println(rkzeroctx.GetTracer(req))

	// 11: get trace provider
	printIndex("[11]: get trace provider")
	fmt.Println(rkzeroctx.GetTracerProvider(req))

	// 12: get tracer propagator
	printIndex("[12]: get tracer propagator")
	fmt.Println(rkzeroctx.GetTracerPropagator(req))

	// 13: inject span
	printIndex("[13]: inject span")
	newReq := &http.Request{}
	rkzeroctx.InjectSpanToHttpRequest(req, newReq)

	// 14: new trace span
	printIndex("[14]: new trace span")
	fmt.Println(rkzeroctx.NewTraceSpan(req, "my-span"))

	// 15: end trace span
	printIndex("[15]: end trace span")
	_, span := rkzeroctx.NewTraceSpan(req, "my-span")
	rkzeroctx.EndTraceSpan(span, true)
}

func printIndex(key string) {
	fmt.Println(fmt.Sprintf("%s", key))
}

func prettyHeader(header http.Header) {
	for k, v := range header {
		fmt.Println(fmt.Sprintf("%s:%s", k, v))
	}
}
