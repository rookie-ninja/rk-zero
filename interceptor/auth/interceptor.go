// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

// Package rkzeroauth is auth middleware for go-zero framework
package rkzeroauth

import (
	"context"
	"fmt"
	"github.com/rookie-ninja/rk-common/error"
	"github.com/rookie-ninja/rk-zero/interceptor"
	"github.com/tal-tech/go-zero/rest"
	"github.com/tal-tech/go-zero/rest/httpx"
	"net/http"
	"strings"
)

// Interceptor validate bellow authorization.
//
// 1: Basic Auth: The client sends HTTP requests with the Authorization header that contains the word Basic, followed by a space and a base64-encoded(non-encrypted) string username: password.
// 2: Bearer Token: Commonly known as token authentication. It is an HTTP authentication scheme that involves security tokens called bearer tokens.
// 3: API key: An API key is a token that a client provides when making API calls. With API key auth, you send a key-value pair to the API in the request headers.
func Interceptor(opts ...Option) rest.Middleware {
	set := newOptionSet(opts...)

	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(writer http.ResponseWriter, req *http.Request) {
			// wrap writer
			writer = rkzerointer.WrapResponseWriter(writer)

			ctx := context.WithValue(req.Context(), rkzerointer.RpcEntryNameKey, set.EntryName)
			req = req.WithContext(ctx)

			err := before(req, writer, set)

			if err == nil {
				next(writer, req)
			}
		}
	}
}

func before(req *http.Request, writer http.ResponseWriter, set *optionSet) error {
	if !set.ShouldAuth(req) {
		return nil
	}

	authHeader := req.Header.Get(rkzerointer.RpcAuthorizationHeaderKey)
	apiKeyHeader := req.Header.Get(rkzerointer.RpcApiKeyHeaderKey)

	if len(authHeader) > 0 {
		// Contains auth header
		// Basic auth type
		tokens := strings.SplitN(authHeader, " ", 2)
		if len(tokens) != 2 {
			resp := rkerror.New(
				rkerror.WithHttpCode(http.StatusUnauthorized),
				rkerror.WithMessage("Invalid Basic Auth format"))

			httpx.WriteJson(writer, http.StatusUnauthorized, resp)

			return resp.Err
		}
		if !set.Authorized(tokens[0], tokens[1]) {
			if tokens[0] == typeBasic {
				writer.Header().Set("WWW-Authenticate", fmt.Sprintf(`%s realm="%s"`, typeBasic, set.BasicRealm))
			}

			resp := rkerror.New(
				rkerror.WithHttpCode(http.StatusUnauthorized),
				rkerror.WithMessage("Invalid credential"))

			httpx.WriteJson(writer, http.StatusUnauthorized, resp)

			return resp.Err
		}
	} else if len(apiKeyHeader) > 0 {
		// Contains api key
		if !set.Authorized(typeApiKey, apiKeyHeader) {
			resp := rkerror.New(
				rkerror.WithHttpCode(http.StatusUnauthorized),
				rkerror.WithMessage("Invalid X-API-Key"))

			httpx.WriteJson(writer, http.StatusUnauthorized, resp)

			return resp.Err
		}
	} else {
		authHeaders := []string{}
		if len(set.BasicAccounts) > 0 {
			writer.Header().Set("WWW-Authenticate", fmt.Sprintf(`%s realm="%s"`, typeBasic, set.BasicRealm))
			authHeaders = append(authHeaders, "Basic Auth")
		}
		if len(set.ApiKey) > 0 {
			authHeaders = append(authHeaders, "X-API-Key")
		}

		errMsg := fmt.Sprintf("Missing authorization, provide one of bellow auth header:[%s]", strings.Join(authHeaders, ","))

		resp := rkerror.New(
			rkerror.WithHttpCode(http.StatusUnauthorized),
			rkerror.WithMessage(errMsg))

		httpx.WriteJson(writer, http.StatusUnauthorized, resp)

		return resp.Err
	}

	return nil
}
