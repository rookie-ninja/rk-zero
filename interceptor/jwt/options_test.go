// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

package rkzerojwt

import (
	"bytes"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func TestNewOptionSet(t *testing.T) {
	// without options
	set := newOptionSet()
	assert.NotEmpty(t, set.EntryName)
	assert.NotEmpty(t, set.EntryType)
	assert.False(t, set.Skipper(&http.Request{URL: &url.URL{
		Path: "ut-path",
	}}))
	assert.Empty(t, set.SigningKeys)
	assert.Nil(t, set.SigningKey)
	assert.Equal(t, set.SigningAlgorithm, AlgorithmHS256)
	assert.NotNil(t, set.Claims)
	assert.Equal(t, set.TokenLookup, "header:"+headerAuthorization)
	assert.Equal(t, set.AuthScheme, "Bearer")
	assert.Equal(t, reflect.ValueOf(set.KeyFunc).Pointer(), reflect.ValueOf(set.defaultKeyFunc).Pointer())
	assert.Equal(t, reflect.ValueOf(set.ParseTokenFunc).Pointer(), reflect.ValueOf(set.defaultParseToken).Pointer())

	// with options
	skipper := func(*http.Request) bool {
		return false
	}
	claims := &fakeClaims{}
	keyFunc := func(token *jwt.Token) (interface{}, error) {
		return nil, nil
	}
	parseToken := func(string, *http.Request) (*jwt.Token, error) { return nil, nil }
	tokenLookups := strings.Join([]string{
		"query:ut-query",
		"param:ut-param",
		"cookie:ut-cookie",
		"form:ut-form",
		"header:ut-header",
	}, ",")

	set = newOptionSet(
		WithEntryNameAndType("ut-entry", "ut-type"),
		WithSkipper(skipper),
		WithSigningKey("ut-signing-key"),
		WithSigningKeys("ut-key", "ut-value"),
		WithSigningAlgorithm("ut-signing-algorithm"),
		WithClaims(claims),
		WithTokenLookup(tokenLookups),
		WithAuthScheme("ut-auth-scheme"),
		WithKeyFunc(keyFunc),
		WithParseTokenFunc(parseToken),
		WithIgnorePrefix("/ut"))

	assert.Equal(t, "ut-entry", set.EntryName)
	assert.Equal(t, "ut-type", set.EntryType)
	assert.False(t, set.Skipper(&http.Request{URL: &url.URL{
		Path: "ut-path",
	}}))
	assert.Equal(t, "ut-signing-key", set.SigningKey)
	assert.NotEmpty(t, set.SigningKeys)
	assert.Equal(t, "ut-signing-algorithm", set.SigningAlgorithm)
	assert.Equal(t, claims, set.Claims)
	assert.Equal(t, tokenLookups, set.TokenLookup)
	assert.Len(t, set.extractors, 5)
	assert.Equal(t, "ut-auth-scheme", set.AuthScheme)
	assert.Equal(t, reflect.ValueOf(set.KeyFunc).Pointer(), reflect.ValueOf(keyFunc).Pointer())
	assert.Equal(t, reflect.ValueOf(set.ParseTokenFunc).Pointer(), reflect.ValueOf(parseToken).Pointer())
}

func TestJwtFromHeader(t *testing.T) {
	headerKey := "ut-header"
	authScheme := "ut-auth-scheme"
	jwtValue := "ut-jwt"
	extractor := jwtFromHeader(headerKey, authScheme)
	req, _ := newReqAndWriter()

	// happy case
	req.Header.Set(headerKey, strings.Join([]string{authScheme, jwtValue}, " "))
	res, err := extractor(req)
	assert.Equal(t, jwtValue, res)
	assert.Nil(t, err)

	// invalid auth
	req.Header.Set(headerKey, strings.Join([]string{"invalid", jwtValue}, " "))
	res, err = extractor(req)
	assert.Empty(t, res)
	assert.NotNil(t, err)
}

func TestJwtFromQuery(t *testing.T) {
	queryKey := "ut-query"
	jwtValue := "ut-jwt"
	extractor := jwtFromQuery(queryKey)
	req, _ := newReqAndWriter()

	// happy case
	req.URL.RawQuery = strings.Join([]string{queryKey, jwtValue}, "=")
	res, err := extractor(req)
	assert.Equal(t, jwtValue, res)
	assert.Nil(t, err)

	// invalid auth
	req, _ = newReqAndWriter()
	req.URL.RawQuery = strings.Join([]string{"invalid", jwtValue}, "=")
	res, err = extractor(req)
	assert.Empty(t, res)
	assert.NotNil(t, err)
}

func TestJwtFromParam(t *testing.T) {
	paramKey := "ut-param"
	jwtValue := "ut-jwt"
	extractor := jwtFromParam(paramKey)
	req, _ := newReqAndWriter()

	// happy case
	req.URL = &url.URL{
		RawQuery: fmt.Sprintf("%s=%s", paramKey, jwtValue),
	}

	res, err := extractor(req)
	assert.Equal(t, jwtValue, res)
	assert.Nil(t, err)

	// invalid auth
	req, _ = newReqAndWriter()
	req.URL = &url.URL{
		RawQuery: fmt.Sprintf("%s=%s", "invalid", jwtValue),
	}
	res, err = extractor(req)
	assert.Empty(t, res)
	assert.NotNil(t, err)
}

func TestJwtFromCookie(t *testing.T) {
	cookieKey := "ut-cookie"
	jwtValue := "ut-jwt"
	extractor := jwtFromCookie(cookieKey)
	req, _ := newReqAndWriter()

	// happy case
	req.AddCookie(&http.Cookie{
		Name:  cookieKey,
		Value: jwtValue,
	})
	res, err := extractor(req)
	assert.Equal(t, jwtValue, res)
	assert.Nil(t, err)

	// invalid auth
	req, _ = newReqAndWriter()
	req.AddCookie(&http.Cookie{
		Name:  "invalid",
		Value: jwtValue,
	})
	res, err = extractor(req)
	assert.Empty(t, res)
	assert.NotNil(t, err)
}

func TestJwtFromForm(t *testing.T) {
	formKey := "ut-form"
	jwtValue := "ut-jwt"
	extractor := jwtFromForm(formKey)
	req, _ := newReqAndWriter()

	// happy case
	req.Form = url.Values{
		formKey: []string{jwtValue},
	}
	res, err := extractor(req)
	assert.Equal(t, jwtValue, res)
	assert.Nil(t, err)

	// invalid auth
	req, _ = newReqAndWriter()
	req.Form = url.Values{
		"invalid": []string{jwtValue},
	}
	res, err = extractor(req)
	assert.Empty(t, res)
	assert.NotNil(t, err)
}

func newReqAndWriter() (*http.Request, *httptest.ResponseRecorder) {
	var buf bytes.Buffer
	req := httptest.NewRequest(http.MethodPost, "/ut-path", &buf)
	writer := httptest.NewRecorder()
	return req, writer
}

type fakeClaims struct{}

func (c *fakeClaims) Valid() error {
	return nil
}