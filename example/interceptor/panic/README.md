# Panic interceptor
In this example, we will try to create rk-zero server with panic interceptor enabled.

Panic interceptor will add do the bellow actions.
- Recover from panic
- Convert interface to standard rkerror.ErrorResp style of error
- Set resCode to 500
- Print stacktrace
- Set [panic:1] into event as counters
- Add error into event

**Please make sure panic interceptor to be added at last in chain of interceptors.**

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**  *generated with [DocToc](https://github.com/thlorenz/doctoc)*

- [Quick start](#quick-start)
  - [Code](#code)
- [Example](#example)
  - [Start server](#start-server)
  - [Output](#output)
  - [Code](#code-1)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## Quick start
Get rk-zero package from the remote repository.

```go
go get -u github.com/rookie-ninja/rk-zero
```
### Code
```go
import     "github.com/rookie-ninja/rk-zero/interceptor/panic"
```
```go
    // ********************************************
    // ********** Enable interceptors *************
    // ********************************************
	interceptors := []rest.Middleware{
        rkzeropanic.Interceptor(),
    }
```

## Example
We will enable log interceptor to monitor RPC.

### Start server
```shell script
$ go run greeter-server.go
```

### Output
- Server side log (zap & event)
```shell script
2021-12-26T00:18:43.199+0800    ERROR   panic/interceptor.go:47 panic occurs:
goroutine 31 [running]:
...
created by net/http.(*Server).Serve
        /usr/local/Cellar/go/1.16.3/libexec/src/net/http/server.go:3013 +0x39b
        {"traceId": "be8b238302b52ddb365c81798ec27bbe", "error": "[Internal Server Error] Panic manually!"}
```

```shell script
------------------------------------------------------------------------
endTime=2021-12-26T00:18:43.199633+08:00
startTime=2021-12-26T00:18:43.198837+08:00
elapsedNano=795865
timezone=CST
ids={"eventId":"c3c52604-0b76-4cfe-a2a7-c64cf42a5a5a","traceId":"be8b238302b52ddb365c81798ec27bbe"}
app={"appName":"rk","appVersion":"","entryName":"zero","entryType":"zero"}
env={"arch":"amd64","az":"*","domain":"*","hostname":"lark.local","localIP":"192.168.101.5","os":"darwin","realm":"*","region":"*"}
payloads={"apiMethod":"GET","apiPath":"/rk/v1/greeter","apiProtocol":"HTTP/1.1","apiQuery":"","userAgent":"curl/7.64.1"}
error={"[Internal Server Error] Panic manually!":1}
counters={"panic":1}
pairs={}
timing={}
remoteAddr=localhost:49202
operation=/rk/v1/greeter
resCode=500
eventStatus=Ended
EOE
```

- Client side
```shell script
$ curl "localhost:8080/rk/v1/greeter?name=rk-dev"
{"error":{"code":500,"status":"Internal Server Error","message":"Panic manually!","details":[]}}
```

### Code
- [greeter-server.go](greeter-server.go)
