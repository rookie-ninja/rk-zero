# Secure interceptor
In this example, we will try to create go-zero server with Secure middleware enabled.

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**  *generated with [DocToc](https://github.com/thlorenz/doctoc)*

- [Quick start](#quick-start)
  - [Code](#code)
- [Options](#options)
  - [Context Usage](#context-usage)
- [Example](#example)
    - [Start server](#start-server)
    - [Send request](#send-request)
    - [Code](#code-1)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## Quick start
Get rk-zero package from the remote repository.

```go
go get -u github.com/rookie-ninja/rk-zero
```

### Code
Add rkzerosec.Interceptor() with option.

```go
import     "github.com/rookie-ninja/rk-zero/interceptor/secure"
```
```go
    // ********************************************
    // ********** Enable interceptors *************
    // ********************************************
	interceptors := []rest.Middleware{
		rkzerosec.Interceptor(),
    }
```

## Options
| Name | Description | Default Values |
| ---- | ---- | ---- |
| rkzerosec.WithEntryNameAndType(entryName, entryType string) | Optional. Provide entry name and type if there are multiple secure interceptors needs to be used. | zero, zero |
| rkzerosec.WithXSSProtection(string) | Optional. X-XSS-Protection header value | "1; mode=block" |
| rkzerosec.WithContentTypeNosniff(string) | Optional. X-Content-Type-Options header value | nosniff |
| rkzerosec.WithXFrameOptions(string) | Optional. X-Frame-Options header value | SAMEORIGIN |
| rkzerosec.WithHSTSMaxAge(int) | Optional, Strict-Transport-Security header value | 0 |
| rkzerosec.WithHSTSExcludeSubdomains(bool) | Optional, excluding subdomains of HSTS | false |
| rkzerosec.WithHSTSPreloadEnabled(bool) | Optional, enabling HSTS preload | false |
| rkzerosec.WithContentSecurityPolicy(string) | Optional, Content-Security-Policy header value | "" |
| rkzerosec.WithCSPReportOnly(bool) | Optional, Content-Security-Policy-Report-Only header value | false |
| rkzerosec.WithReferrerPolicy(string) | Optional, Referrer-Policy header value | "" | 
| rkzerosec.WithIgnorePrefix([]string) | Optional, provide ignoring path prefix. | [] |

```go
    // ********************************************
    // ********** Enable interceptors *************
    // ********************************************
	interceptors := []rest.Middleware{
		rkzerosec.Interceptor(
			// Required, entry name and entry type will be used for distinguishing interceptors. Recommended.
			rkzerosec.WithEntryNameAndType("greeter", "zero"),
			//
			// X-XSS-Protection header value.
			// Optional. Default value "1; mode=block".
			//rkzerosec.WithXSSProtection("my-value"),
			//
			// X-Content-Type-Options header value.
			// Optional. Default value "nosniff".
			//rkzerosec.WithContentTypeNosniff("my-value"),
			//
			// X-Frame-Options header value.
			// Optional. Default value "SAMEORIGIN".
			//rkzerosec.WithXFrameOptions("my-value"),
			//
			// Optional, Strict-Transport-Security header value.
			//rkzerosec.WithHSTSMaxAge(1),
			//
			// Optional, excluding subdomains of HSTS, default is false
			//rkzerosec.WithHSTSExcludeSubdomains(true),
			//
			// Optional, enabling HSTS preload, default is false
			//rkzerosec.WithHSTSPreloadEnabled(true),
			//
			// Content-Security-Policy header value.
			// Optional. Default value "".
			//rkzerosec.WithContentSecurityPolicy("my-value"),
			//
			// Content-Security-Policy-Report-Only header value.
			// Optional. Default value false.
			//rkzerosec.WithCSPReportOnly(true),
			//
			// Referrer-Policy header value.
			// Optional. Default value "".
			//rkzerosec.WithReferrerPolicy("my-value"),
			//
			// Ignoring path prefix
			//rkzerosec.WithIgnorePrefix("/rk/v1"),
		),
    }
```

### Context Usage
| Name | Functionality |
| ------ | ------ |
| rkzeroctx.GetLogger(*http.Request, http.ResponseWriter) | Get logger generated by log interceptor. If there are X-Request-Id or X-Trace-Id as headers in incoming and outgoing metadata, then loggers will has requestId and traceId attached by default. |
| rkzeroctx.GetEvent(*http.Request) | Get event generated by log interceptor. Event would be printed as soon as RPC finished. |
| rkzeroctx.GetIncomingHeaders(*http.Request) | Get incoming header. |
| rkzeroctx.AddHeaderToClient(http.ResponseWriter, "k", "v") | Add k/v to headers which would be sent to client. This is append operation. |
| rkzeroctx.SetHeaderToClient(http.ResponseWriter, "k", "v") | Set k/v to headers which would be sent to client. |
| rkzeroctx.GetJwtToken(*http.Request) | Get jwt token if exists |
| rkzeroctx.GetCsrfToken(*http.Request) | Get csrf token if exists |

## Example
#### Start server
```shell script
$ go run greeter-server.go
```

#### Send request
```shell script
$ curl -vs localhost:8080/rk/v1/greeter
  ...
< HTTP/1.1 200 OK
< Content-Type: application/json
< X-Content-Type-Options: nosniff
< X-Frame-Options: SAMEORIGIN
< X-Trace-Id: 0770d96b5d9adcf4be2c06d74c66b7c2
< X-Xss-Protection: 1; mode=block
< Date: Sat, 25 Dec 2021 17:52:26 GMT
< Content-Length: 31
...
{"Message":"Received message!"}
```

#### Code

- [greeter-server.go](greeter-server.go)