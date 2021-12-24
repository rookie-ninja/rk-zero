// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

package rkzerogzip

import (
	"bytes"
	"compress/gzip"
	"github.com/stretchr/testify/assert"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newReqAndWriter(encode bool) (*http.Request, *httptest.ResponseRecorder) {
	var buf bytes.Buffer
	req := httptest.NewRequest(http.MethodPost, "/ut-path", &buf)

	if encode {
		zw := gzip.NewWriter(&buf)
		zw.Write([]byte("ut-string"))
		zw.Flush()
		zw.Close()
		req.Header.Set(headerContentEncoding, gzipEncoding)
		req.Header.Set(headerAcceptEncoding, gzipEncoding)
	} else {
		buf.WriteString("ut-string")
	}

	writer := httptest.NewRecorder()
	return req, writer
}

func TestInterceptor(t *testing.T) {
	//defer assertNotPanic(t)

	// With skipper
	req, writer := newReqAndWriter(false)
	handler := Interceptor(WithSkipper(func(*http.Request) bool {
		return true
	}))
	f := handler(func(writer http.ResponseWriter, request *http.Request) {
		buf := new(bytes.Buffer)
		buf.ReadFrom(request.Body)
		writer.WriteHeader(http.StatusOK)
		writer.Write(buf.Bytes())
	})
	f(writer, req)
	assert.Equal(t, "ut-string", writer.Body.String())

	// without skipper
	req, writer = newReqAndWriter(true)
	handler = Interceptor()
	f = handler(func(writer http.ResponseWriter, request *http.Request) {
		buf := new(bytes.Buffer)
		buf.ReadFrom(request.Body)
		writer.WriteHeader(http.StatusOK)
		writer.Write(buf.Bytes())
	})
	f(writer, req)
	zr, _ := gzip.NewReader(writer.Body)
	var res bytes.Buffer
	io.Copy(&res, zr)
	assert.Equal(t, "ut-string", res.String())

	// with empty response
	req, writer = newReqAndWriter(true)
	handler = Interceptor()

	f = handler(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
		writer.Write([]byte(""))
	})
	f(writer, req)
}
