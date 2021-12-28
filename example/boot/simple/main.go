// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.
package main

import (
	"context"
	"github.com/rookie-ninja/rk-entry/entry"
	"github.com/rookie-ninja/rk-zero/boot"
	"github.com/tal-tech/go-zero/rest"
	"net/http"
)

func main() {
	// Bootstrap basic entries from boot config.
	rkentry.RegisterInternalEntriesFromConfig("example/boot/simple/boot.yaml")

	// Bootstrap zero entry from boot config
	res := rkzero.RegisterZeroEntriesWithConfig("example/boot/simple/boot.yaml")

	// Get ZeroEntry
	zeroEntry := res["greeter"].(*rkzero.ZeroEntry)
	// Add router
	zeroEntry.Server.AddRoute(rest.Route{
		Method: http.MethodGet,
		Path:   "/v1/greeter",
		Handler: func(writer http.ResponseWriter, request *http.Request) {
			writer.WriteHeader(http.StatusOK)
			writer.Write([]byte("Hello!"))
		},
	})

	// Bootstrap zero entry
	zeroEntry.Bootstrap(context.Background())

	// Wait for shutdown signal
	rkentry.GlobalAppCtx.WaitForShutdownSig()

	// Interrupt zero entry
	zeroEntry.Interrupt(context.Background())
}
