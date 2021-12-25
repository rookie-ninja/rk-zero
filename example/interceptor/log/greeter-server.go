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
	"github.com/tal-tech/go-zero/rest"
	"github.com/tal-tech/go-zero/rest/httpx"
	"net/http"
)

// In this example, we will start a new go-zero server with log interceptor enabled.
// Listen on port of 8080 with GET /rk/v1/greeter?name=<xxx>.
func main() {
	// ********************************************
	// ********** Enable interceptors *************
	// ********************************************
	interceptors := []rest.Middleware{
		//rkzerometa.Interceptor(),
		rkzerolog.Interceptor(
			// Entry name and entry type will be used for distinguishing interceptors. Recommended.
			// rkzerolog.WithEntryNameAndType("greeter", "zero"),
			//
			// Zap logger would be logged as JSON format.
			//rkzerolog.WithZapLoggerEncoding(rkzerolog.ENCODING_JSON),
			//
			// Event logger would be logged as JSON format.
			//rkzerolog.WithEventLoggerEncoding(rkzerolog.ENCODING_JSON),
			//
			// Zap logger would be logged to specified path.
			rkzerolog.WithZapLoggerOutputPaths("logs/server-zap.log"),
			//
			// Event logger would be logged to specified path.
			rkzerolog.WithEventLoggerOutputPaths("logs/server-event.log"),
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

// Greeter Handler for greeter.
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

	// *******************************************
	// ********** rpc-scoped event  *************
	// *******************************************
	//
	// Get rkquery.Event which would be printed as soon as request finish.
	// User can call any Add/Set/Get functions on rkquery.Event
	//
	// rkzeroctx.GetEvent(req).AddPair("rk-key", "rk-value")

	// *********************************************
	// ********** Get incoming headers *************
	// *********************************************
	//
	// Read headers sent from client.
	//
	//for k, v := range rkzeroctx.GetIncomingHeaders(req) {
	//	 fmt.Println(fmt.Sprintf("%s: %s", k, v))
	//}

	// *********************************************************
	// ********** Add headers will send to client **************
	// *********************************************************
	//
	// Send headers to client with this function
	//
	//rkzeroctx.AddHeaderToClient(req, "from-server", "value")

	// ***********************************************
	// ********** Get and log request id *************
	// ***********************************************
	//
	// RequestId will be printed on both client and server side.
	//
	//rkzeroctx.SetHeaderToClient(req, rkzeroctx.RequestIdKey, rkcommon.GenerateRequestId())

	httpx.WriteJson(writer, http.StatusOK, &GreeterResponse{
		Message: fmt.Sprintf("Hello %s!", req.URL.Query().Get("name")),
	})
}
