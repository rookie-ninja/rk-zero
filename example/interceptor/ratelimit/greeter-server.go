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
	"github.com/rookie-ninja/rk-zero/interceptor/ratelimit"
	"github.com/tal-tech/go-zero/rest"
	"github.com/tal-tech/go-zero/rest/httpx"
	"net/http"
)

// In this example, we will start a new go-zero server with rate limit interceptor enabled.
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
		rkzerolog.Interceptor(),
		rkzerolimit.Interceptor(
		// Entry name and entry type will be used for distinguishing interceptors. Recommended.
		//rkzerolimit.WithEntryNameAndType("greeter", "zero"),
		//
		// Provide algorithm, rkzerolimit.LeakyBucket and rkzerolimit.TokenBucket was available, default is TokenBucket.
		//rkzerolimit.WithAlgorithm(rkzerolimit.LeakyBucket),
		//
		// Provide request per second, if provide value of zero, then no requests will be pass through and user will receive an error with
		// resource exhausted.
		//rkzerolimit.WithReqPerSec(10),
		//
		// Provide request per second with path name.
		// The name should be full path name. if provide value of zero,
		// then no requests will be pass through and user will receive an error with resource exhausted.
		//rkzerolimit.WithReqPerSecByPath("/rk/v1/greeter", 10),
		//
		// Provide user function of limiter. Returns error if you want to limit the request.
		// Please do not try to set response code since it will be overridden by middleware.
		//rkzerolimit.WithGlobalLimiter(func(*http.Request) error {
		//	return fmt.Errorf("limited by custom limiter")
		//}),
		//
		// Provide user function of limiter by path name.
		// The name should be full path name.
		//rkzerolimit.WithLimiterByPath("/rk/v1/greeter", func(*http.Request) error {
		//	 return nil
		//}),
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
	// ******************************************
	// ********** rpc-scoped logger *************
	// ******************************************
	//
	// RequestId will be printed if enabled by bellow codes.
	// 1: Enable rkzerometa.Interceptor() in server side.
	// 2: rkzeroctx.AddHeaderToClient(ctx, rkzeroctx.RequestIdKey, rkcommon.GenerateRequestId())
	//
	rkzeroctx.GetLogger(req, writer).Info("Received request from client.")

	// Set request id with X-Request-Id to outgoing headers.
	// rkzeroctx.SetHeaderToClient(ctx, rkzeroctx.RequestIdKey, "this-is-my-request-id-overridden")

	httpx.WriteJson(writer, http.StatusOK, &GreeterResponse{
		Message: fmt.Sprintf("Hello %s!", req.URL.Query().Get("name")),
	})
}
