// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"github.com/rookie-ninja/rk-entry/entry"
	rkzeroctx "github.com/rookie-ninja/rk-zero/interceptor/context"
	rkzerojwt "github.com/rookie-ninja/rk-zero/interceptor/jwt"
	"github.com/tal-tech/go-zero/rest"
	"github.com/tal-tech/go-zero/rest/httpx"
	"net/http"
)

// In this example, we will start a new go-zero server with jwt interceptor enabled.
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
		//rkzerolog.Interceptor(),
		rkzerojwt.Interceptor(
			// Required, entry name and entry type will be used for distinguishing interceptors. Recommended.
			//rkzerojwt.WithEntryNameAndType("greeter", "zero"),
			//
			// Required, provide signing key.
			rkzerojwt.WithSigningKey([]byte("my-secret")),
			//
			// Optional, provide skipper function
			//rkzerojwt.WithSkipper(func(*http.Request) bool {
			//	return true
			//}),
			//
			// Optional, provide token parse function, default one will be assigned.
			//rkzerojwt.WithParseTokenFunc(func(auth string, req *http.Request) (*jwt.Token, error) {
			//	return nil, nil
			//}),
			//
			// Optional, provide key function, default one will be assigned.
			//rkzerojwt.WithKeyFunc(func(token *jwt.Token) (interface{}, error) {
			//	return nil, nil
			//}),
			//
			// Optional, default is Bearer
			//rkzerojwt.WithAuthScheme("Bearer"),
			//
			// Optional
			//rkzerojwt.WithTokenLookup("header:my-jwt-header-key"),
			//
			// Optional, default is HS256
			//rkzerojwt.WithSigningAlgorithm(rkzerojwt.AlgorithmHS256),
		),
	}

	// 1: Create zero server
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
		Message: fmt.Sprintf("Is token valid:%v!", rkzeroctx.GetJwtToken(req).Valid),
	})
}
