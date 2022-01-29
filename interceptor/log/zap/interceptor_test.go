// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

package rkzerolog

import (
	"github.com/rookie-ninja/rk-entry/entry"
	rkmidlog "github.com/rookie-ninja/rk-entry/middleware/log"
	"github.com/rookie-ninja/rk-query"
	rkzeroctx "github.com/rookie-ninja/rk-zero/interceptor/context"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"net/http"
	"net/http/httptest"
	"testing"
)

var userHandler = func(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func TestInterceptor(t *testing.T) {
	defer assertNotPanic(t)

	beforeCtx := rkmidlog.NewBeforeCtx()
	afterCtx := rkmidlog.NewAfterCtx()
	mock := rkmidlog.NewOptionSetMock(beforeCtx, afterCtx)
	inter := Interceptor(rkmidlog.WithMockOptionSet(mock))
	req, w := newReqAndWriter()

	// happy case
	event := rkentry.NoopEventLoggerEntry().GetEventFactory().CreateEventNoop()
	logger := rkentry.NoopZapLoggerEntry().GetLogger()
	beforeCtx.Output.Event = event
	beforeCtx.Output.Logger = logger

	var eventFromCtx rkquery.Event
	var loggerFromCtx *zap.Logger
	inter(func(w http.ResponseWriter, req *http.Request) {
		eventFromCtx = rkzeroctx.GetEvent(req)
		loggerFromCtx = rkzeroctx.GetLogger(req, w)
		w.WriteHeader(http.StatusOK)
	})(w, req)

	assert.Equal(t, event, eventFromCtx)
	assert.Equal(t, logger, loggerFromCtx)

	assert.Equal(t, http.StatusOK, w.Code)
}

func newReqAndWriter() (*http.Request, *httptest.ResponseRecorder) {
	req := httptest.NewRequest(http.MethodGet, "/ut-path", nil)
	req.Header = http.Header{}
	writer := httptest.NewRecorder()
	return req, writer
}

func assertNotPanic(t *testing.T) {
	if r := recover(); r != nil {
		// Expect panic to be called with non nil error
		assert.True(t, false)
	} else {
		// This should never be called in case of a bug
		assert.True(t, true)
	}
}
