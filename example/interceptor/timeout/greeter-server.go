// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.
package main

import (
	"fmt"
	"github.com/rookie-ninja/rk-entry/entry"
	"github.com/rookie-ninja/rk-zero/interceptor/context"
	"github.com/rookie-ninja/rk-zero/interceptor/log/zap"
	"github.com/rookie-ninja/rk-zero/interceptor/panic"
	"github.com/rookie-ninja/rk-zero/interceptor/timeout"
	"github.com/tal-tech/go-zero/rest"
	"github.com/tal-tech/go-zero/rest/httpx"
	"net/http"
	"time"
)

// In this example, we will start a new gin server with rate limit interceptor enabled.
// Listen on port of 8080 with GET /rk/v1/greeter?name=<xxx>.
func main() {
	// ******************************************************
	// ********** Override App name and version *************
	// ******************************************************
	//
	// rkentry.GlobalAppCtx.GetAppInfoEntry().AppName = "demo-app"
	// rkentry.GlobalAppCtx.GetAppInfoEntry().Version = "demo-version"

	// ********************************************
	// ********** Enable interceptors *************
	// ********************************************
	interceptors := []rest.Middleware{
		rkzeropanic.Interceptor(),
		rkzerolog.Interceptor(),
		rkzerotimeout.Interceptor(
		// Entry name and entry type will be used for distinguishing interceptors. Recommended.
		//rkzerotimeout.WithEntryNameAndType("greeter", "zero"),
		//
		// Provide timeout and response handler, a default one would be assigned with http.StatusRequestTimeout
		// This option impact all routes
		//rkzerotimeout.WithTimeoutAndResp(time.Second, nil),
		//
		// Provide timeout and response handler by path, a default one would be assigned with http.StatusRequestTimeout
		//rkzerotimeout.WithTimeoutAndRespByPath("/rk/v1/healthy", time.Second, nil),
		),
	}

	// 1: Create gin server
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
	// ******************************************
	// ********** rpc-scoped logger *************
	// ******************************************
	//
	// RequestId will be printed if enabled by bellow codes.
	// 1: Enable rkzerometa.Interceptor() in server side.
	// 2: rkzeroctx.SetHeaderToClient(ctx, rkzeroctx.RequestIdKey, rkcommon.GenerateRequestId())
	//
	rkzeroctx.GetLogger(req, writer).Info("Received request from client.")

	// Set request id with X-Request-Id to outgoing headers.
	// rkzeroctx.SetHeaderToClient(ctx, rkzeroctx.RequestIdKey, "this-is-my-request-id-overridden")

	// Sleep for 5 seconds waiting to be timed out by interceptor
	time.Sleep(10 * time.Second)

	httpx.WriteJson(writer, http.StatusOK, &GreeterResponse{
		Message: fmt.Sprintf("Hello %s!", req.URL.Query().Get("name")),
	})
}
