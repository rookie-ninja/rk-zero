// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

package main

import (
	"github.com/rookie-ninja/rk-entry/entry"
	"github.com/rookie-ninja/rk-zero/interceptor/context"
	"github.com/rookie-ninja/rk-zero/interceptor/secure"
	"github.com/tal-tech/go-zero/rest"
	"github.com/tal-tech/go-zero/rest/httpx"
	"net/http"
)

// In this example, we will start a new go-zero server with secure interceptor enabled.
// Listen on port of 8080 with GET /rk/v1/greeter.
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
		rkzerosec.Interceptor(
			// Required, entry name and entry type will be used for distinguishing interceptors. Recommended.
			rkzerosec.WithEntryNameAndType("greeter", "zero"),
			//
			// X-XSS-Protection header value.
			// Optional. Default value "1; mode=block".
			//rkzerosec.WithXSSProtection("my-value"),
			//
			// X-Content-Type-Options header value.
			// Optional. Default value "nosniff".
			//rkzerosec.WithContentTypeNosniff("my-value"),
			//
			// X-Frame-Options header value.
			// Optional. Default value "SAMEORIGIN".
			//rkzerosec.WithXFrameOptions("my-value"),
			//
			// Optional, Strict-Transport-Security header value.
			//rkzerosec.WithHSTSMaxAge(1),
			//
			// Optional, excluding subdomains of HSTS, default is false
			//rkzerosec.WithHSTSExcludeSubdomains(true),
			//
			// Optional, enabling HSTS preload, default is false
			//rkzerosec.WithHSTSPreloadEnabled(true),
			//
			// Content-Security-Policy header value.
			// Optional. Default value "".
			//rkzerosec.WithContentSecurityPolicy("my-value"),
			//
			// Content-Security-Policy-Report-Only header value.
			// Optional. Default value false.
			//rkzerosec.WithCSPReportOnly(true),
			//
			// Referrer-Policy header value.
			// Optional. Default value "".
			//rkzerosec.WithReferrerPolicy("my-value"),
			//
			// Ignoring path prefix.
			//rkzerosec.WithIgnorePrefix("/rk/v1"),
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
	rkzeroctx.GetLogger(req, writer).Info("Received request from client.")

	httpx.WriteJson(writer, http.StatusOK, &GreeterResponse{
		Message: "Received message!",
	})
}
