// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.
package main

import (
	"context"
	_ "embed"
	"fmt"
	"github.com/rookie-ninja/rk-entry/v2/entry"
	"github.com/rookie-ninja/rk-zero/v2/boot"
	"github.com/rookie-ninja/rk-zero/v2/middleware/context"
	"github.com/zeromicro/go-zero/rest"
	"github.com/zeromicro/go-zero/rest/httpx"
	"net/http"
)

//go:embed boot.yaml
var boot []byte

func main() {
	// Bootstrap preload entries
	rkentry.BootstrapPreloadEntryYAML(boot)

	// Bootstrap zero entry from boot config
	res := rkzero.RegisterZeroEntryYAML(boot)

	// Register GET and POST method of /rk/v1/greeter
	entry := res["greeter"].(*rkzero.ZeroEntry)

	entry.Server.AddRoute(rest.Route{
		Method:  http.MethodGet,
		Path:    "/rk/v1/greeter",
		Handler: Greeter,
	})
	entry.Server.AddRoute(rest.Route{
		Method:  http.MethodPost,
		Path:    "/rk/v1/greeter",
		Handler: Greeter,
	})

	// Bootstrap go-zero entry
	res["greeter"].Bootstrap(context.Background())

	// Wait for shutdown signal
	rkentry.GlobalAppCtx.WaitForShutdownSig()

	// Interrupt go-zero entry
	res["greeter"].Interrupt(context.Background())
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
