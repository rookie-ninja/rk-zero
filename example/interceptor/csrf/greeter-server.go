// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"github.com/rookie-ninja/rk-entry/entry"
	"github.com/rookie-ninja/rk-zero/interceptor/context"
	"github.com/rookie-ninja/rk-zero/interceptor/csrf"
	"github.com/tal-tech/go-zero/rest"
	"github.com/tal-tech/go-zero/rest/httpx"
	"net/http"
)

// In this example, we will start a new go-zero server with csrf interceptor enabled.
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
		rkzerocsrf.Interceptor(
			// Required, entry name and entry type will be used for distinguishing interceptors. Recommended.
			rkzerocsrf.WithEntryNameAndType("greeter", "zero"),
			//
			// Optional, provide skipper function
			//rkzerocsrf.WithSkipper(func(req *http.Request) bool {
			//	return true
			//}),
			//
			// WithTokenLength the length of the generated token.
			// Optional. Default value 32.
			//rkzerocsrf.WithTokenLength(10),
			//
			// WithTokenLookup a string in the form of "<source>:<key>" that is used
			// to extract token from the request.
			// Optional. Default value "header:X-CSRF-Token".
			// Possible values:
			// - "header:<name>"
			// - "form:<name>"
			// - "query:<name>"
			// Optional. Default value "header:X-CSRF-Token".
			//rkzerocsrf.WithTokenLookup("header:X-CSRF-Token"),
			//
			// WithCookieName provide name of the CSRF cookie. This cookie will store CSRF token.
			// Optional. Default value "csrf".
			//rkzerocsrf.WithCookieName("csrf"),
			//
			// WithCookieDomain provide domain of the CSRF cookie.
			// Optional. Default value "".
			//rkzerocsrf.WithCookieDomain(""),
			//
			// WithCookiePath provide path of the CSRF cookie.
			// Optional. Default value "".
			//rkzerocsrf.WithCookiePath(""),
			//
			// WithCookieMaxAge provide max age (in seconds) of the CSRF cookie.
			// Optional. Default value 86400 (24hr).
			//rkzerocsrf.WithCookieMaxAge(10),
			//
			// WithCookieHTTPOnly indicates if CSRF cookie is HTTP only.
			// Optional. Default value false.
			//rkzerocsrf.WithCookieHTTPOnly(false),
			//
			// WithCookieSameSite indicates SameSite mode of the CSRF cookie.
			// Optional. Default value SameSiteDefaultMode.
			//rkzerocsrf.WithCookieSameSite(http.SameSiteStrictMode),
		),
	}

	// 1: Create go-zero server
	server := startGreeterServer(interceptors...)
	defer server.Stop()

	// 2: Wait for ctrl-C to shutdown server
	rkentry.GlobalAppCtx.WaitForShutdownSig()
}

// Start zero server.
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
		Method:  http.MethodPost,
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
		Message: fmt.Sprintf("CSRF token:%v", rkzeroctx.GetCsrfToken(req)),
	})
}
