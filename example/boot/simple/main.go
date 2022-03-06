// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.
package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"github.com/rookie-ninja/rk-entry/v2/entry"
	"github.com/rookie-ninja/rk-zero/v2/boot"
	"github.com/zeromicro/go-zero/rest"
	"net/http"
)

//go:embed boot.yaml
var boot []byte

////go:embed docs
//var docsFS embed.FS
//
////go:embed docs
//var staticFS embed.FS

func init() {
	//rkentry.GlobalAppCtx.AddEmbedFS(rkentry.DocsEntryType, "greeter", &docsFS)
	//rkentry.GlobalAppCtx.AddEmbedFS(rkentry.SWEntryType, "greeter", &docsFS)
	//rkentry.GlobalAppCtx.AddEmbedFS(rkentry.StaticFileHandlerEntryType, "greeter", &staticFS)
}

func main() {
	// Bootstrap preload entries
	rkentry.BootstrapPreloadEntryYAML(boot)

	// Bootstrap zero entry from boot config
	res := rkzero.RegisterZeroEntryYAML(boot)

	// Get ZeroEntry
	zeroEntry := res["greeter"].(*rkzero.ZeroEntry)
	// Add router
	zeroEntry.Server.AddRoute(rest.Route{
		Method:  http.MethodGet,
		Path:    "/v1/greeter",
		Handler: Greeter,
	})

	// Bootstrap zero entry
	zeroEntry.Bootstrap(context.Background())

	// Wait for shutdown signal
	rkentry.GlobalAppCtx.WaitForShutdownSig()

	// Interrupt zero entry
	zeroEntry.Interrupt(context.Background())
}

func Greeter(writer http.ResponseWriter, request *http.Request) {
	writer.WriteHeader(http.StatusOK)
	resp := &GreeterResponse{
		Message: fmt.Sprintf("Hello %s!", request.URL.Query().Get("name")),
	}
	bytes, _ := json.Marshal(resp)
	writer.Write(bytes)
}

type GreeterResponse struct {
	Message string
}
