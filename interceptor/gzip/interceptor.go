// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

// Package rkzerogzip is a middleware for go-zero framework which compress/decompress data for RPC
package rkzerogzip

import (
	"bytes"
	"context"
	"github.com/rookie-ninja/rk-common/error"
	"github.com/rookie-ninja/rk-zero/interceptor"
	"github.com/tal-tech/go-zero/rest"
	"github.com/tal-tech/go-zero/rest/httpx"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
)

// Interceptor Add gzip compress and decompress interceptors.
//
// Mainly copied from bellow.
// https://github.com/labstack/echo/blob/master/middleware/decompress.go
// https://github.com/labstack/echo/blob/master/middleware/compress.go
func Interceptor(opts ...Option) rest.Middleware {
	set := newOptionSet(opts...)

	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(writer http.ResponseWriter, req *http.Request) {
			// wrap writer
			writer = rkzerointer.WrapResponseWriter(writer)

			ctx := context.WithValue(req.Context(), rkzerointer.RpcEntryNameKey, set.EntryName)
			req = req.WithContext(ctx)

			if set.Skipper(req) {
				next(writer, req)
				return
			}

			// deal with request decompression
			switch req.Header.Get(headerContentEncoding) {
			case gzipEncoding:
				gzipReader := set.decompressPool.Get()

				// make gzipReader to read from original request body
				if err := gzipReader.Reset(req.Body); err != nil {
					// return reader back to sync.Pool
					set.decompressPool.Put(gzipReader)

					// body is empty, keep on going
					if err == io.EOF {
						next(writer, req)
						return
					}

					httpx.WriteJson(writer, http.StatusInternalServerError, rkerror.New(
						rkerror.WithHttpCode(http.StatusInternalServerError),
						rkerror.WithDetails(err)))
					return
				}

				// create a buffer and copy decompressed data into it via gzipReader
				var buf bytes.Buffer
				if _, err := io.Copy(&buf, gzipReader); err != nil {
					httpx.WriteJson(writer, http.StatusInternalServerError, rkerror.New(
						rkerror.WithHttpCode(http.StatusInternalServerError),
						rkerror.WithDetails(err)))
					return
				}

				// close both gzipReader and original reader in request body
				gzipReader.Close()
				req.Body.Close()
				set.decompressPool.Put(gzipReader)

				// assign decompressed buffer to request
				req.Body = ioutil.NopCloser(&buf)
			}

			// deal with response compression
			writer.Header().Add(headerVary, headerAcceptEncoding)
			// gzip is one of expected encoding type from request
			if strings.Contains(req.Header.Get(headerAcceptEncoding), gzipEncoding) {
				// set to response header
				writer.Header().Set(headerContentEncoding, gzipEncoding)

				// create gzip writer
				gzipWriter := set.compressPool.Get()

				// reset writer of gzip writer to original writer from response
				originalWriter := writer
				gzipWriter.Reset(originalWriter)

				// defer func
				defer func() {
					// must be RkResponseWriter
					//if writer.(*gzipResponseWriter).Writer.(*rkzerointer.RkResponseWriter).Size.Get() == 0 {
					//	// remove encoding header if response is empty
					//	if writer.Header().Get(headerContentEncoding) == gzipEncoding {
					//		writer.Header().Del(headerContentEncoding)
					//	}
					//	// we have to reset response to it's pristine state when
					//	// nothing is written to body or error is returned.
					//	writer = originalWriter
					//
					//	// reset to empty
					//	gzipWriter.Reset(ioutil.Discard)
					//}

					// close gzipWriter
					gzipWriter.Close()

					// put gzipWriter back to pool
					set.compressPool.Put(gzipWriter)
				}()

				// assign new writer to response
				writer = newGzipResponseWriter(gzipWriter, originalWriter)
			}

			next(writer, req)
		}
	}
}
