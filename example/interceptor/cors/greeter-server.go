// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"github.com/rookie-ninja/rk-entry/entry"
	"github.com/rookie-ninja/rk-zero/interceptor/context"
	"github.com/rookie-ninja/rk-zero/interceptor/cors"
	"github.com/tal-tech/go-zero/rest"
	"github.com/tal-tech/go-zero/rest/httpx"
	"net/http"
)

// In this example, we will start a new go-zero server with cors interceptor enabled.
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
		rkzerocors.Interceptor(
			// Entry name and entry type will be used for distinguishing interceptors. Recommended.
			rkzerocors.WithEntryNameAndType("greeter", "zero"),
			// Provide skipper function
			// rkzerocors.WithSkipper(func(req *http.Request) bool {
			//     return false
			// }),
			// Bellow section is for CORS policy.
			// Please refer https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS for details.
			// Provide allowed origins
			rkzerocors.WithAllowOrigins("http://localhost:*"),
			// Whether to allow credentials
			// rkzerocors.WithAllowCredentials(true),
			// Provide expose headers
			// rkzerocors.WithExposeHeaders(""),
			// Provide max age
			// rkzerocors.WithMaxAge(1),
			// Provide allowed headers
			// rkzerocors.WithAllowHeaders(""),
			// Provide allowed headers
			// rkzerocors.WithAllowMethods(""),
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
	server.AddRoute(rest.Route{
		Method:  http.MethodOptions,
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
	// 2: rkzeroctx.SetHeaderToClient(writer, rkzeroctx.RequestIdKey, rkcommon.GenerateRequestId())
	//
	rkzeroctx.GetLogger(req, writer).Info("Received request from client.")

	httpx.WriteJson(writer, http.StatusOK, &GreeterResponse{
		Message: fmt.Sprintf("Hello %s!", req.URL.Query().Get("name")),
	})
}
