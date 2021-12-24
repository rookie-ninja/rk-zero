// Copyright (c) 2021 rookie-ninja
//
// Use of this source code is governed by an Apache-style
// license that can be found in the LICENSE file.

// Package rkzero is a static files which aims to include assets files into pkger
package rkzero

import "github.com/markbates/pkger"

func init() {
	pkger.Include("/boot/assets/")
}
