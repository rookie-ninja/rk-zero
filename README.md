# rk-zero
[![build](https://github.com/rookie-ninja/rk-zero/actions/workflows/ci.yml/badge.svg)](https://github.com/rookie-ninja/rk-zero/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/rookie-ninja/rk-zero/branch/master/graph/badge.svg?token=Y1HM9UQBX6)](https://codecov.io/gh/rookie-ninja/rk-zero)
[![Go Report Card](https://goreportcard.com/badge/github.com/rookie-ninja/rk-zero)](https://goreportcard.com/report/github.com/rookie-ninja/rk-zero)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

> In testing stage!

Interceptor & bootstrapper designed for [zeromicro/go-zero](https://github.com/zeromicro/go-zero) framework. Currently, supports bellow functionalities.

This belongs to [rk-boot](https://github.com/rookie-ninja/rk-boot) family. We suggest use this lib from [rk-boot](https://github.com/rookie-ninja/rk-boot).

![image](docs/img/boot-arch.png)

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**  *generated with [DocToc](https://github.com/thlorenz/doctoc)*

- [Architecture](#architecture)
- [Supported bootstrap](#supported-bootstrap)
- [Supported instances](#supported-instances)
- [Supported middlewares](#supported-middlewares)
- [Installation](#installation)
- [Quick Start](#quick-start)
  - [1.Create boot.yaml](#1create-bootyaml)
  - [2.Create main.go](#2create-maingo)
  - [3.Start server](#3start-server)
  - [4.Validation](#4validation)
    - [4.1 GoZero server](#41-gozero-server)
    - [4.2 Swagger UI](#42-swagger-ui)
    - [4.3 TV](#43-tv)
    - [4.4 Prometheus Metrics](#44-prometheus-metrics)
    - [4.5 Logging](#45-logging)
    - [4.6 Meta](#46-meta)
    - [4.7 Send request](#47-send-request)
    - [4.8 RPC logs](#48-rpc-logs)
    - [4.9 RPC prometheus metrics](#49-rpc-prometheus-metrics)
- [YAML Options](#yaml-options)
  - [go-zero](#go-zero)
  - [CommonService](#commonservice)
  - [Swagger](#swagger)
  - [Prometheus Client](#prometheus-client)
  - [TV](#tv)
  - [Middlewares](#middlewares)
    - [Log](#log)
    - [Metrics](#metrics)
    - [Auth](#auth)
    - [Meta](#meta)
    - [Tracing](#tracing)
    - [RateLimit](#ratelimit)
    - [Timeout](#timeout)
    - [CORS](#cors)
    - [JWT](#jwt)
    - [Secure](#secure)
    - [CSRF](#csrf)
  - [Full YAML](#full-yaml)
- [Development Status: Testing](#development-status-testing)
- [Build instruction](#build-instruction)
- [Test instruction](#test-instruction)
- [Contributing](#contributing)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## Architecture
![image](docs/img/zero-arch.png)

## Supported bootstrap
| Bootstrap | Description |
| --- | --- |
| YAML based | Start [zeromicro/go-zero](https://github.com/zeromicro/go-zero) microservice from YAML |
| Code based | Start [zeromicro/go-zero](https://github.com/zeromicro/go-zero) microservice from code |

## Supported instances
All instances could be configured via YAML or Code.

**User can enable anyone of those as needed! No mandatory binding!**

| Instance | Description |
| --- | --- |
| rest.Server | Compatible with original [zeromicro/go-zero](https://github.com/zeromicro/go-zero) service functionalities |
| Config | Configure [spf13/viper](https://github.com/spf13/viper) as config instance and reference it from YAML |
| Logger | Configure [uber-go/zap](https://github.com/uber-go/zap) logger configuration and reference it from YAML |
| EventLogger | Configure logging of RPC with [rk-query](https://github.com/rookie-ninja/rk-query) and reference it from YAML |
| Credential | Fetch credentials from remote datastore like ETCD. |
| Cert | Fetch TLS/SSL certificates from remote datastore like ETCD and start microservice. |
| Prometheus | Start prometheus client at client side and push metrics to pushgateway as needed. |
| Swagger | Builtin swagger UI handler. |
| CommonService | List of common APIs. |
| TV | A Web UI shows microservice and environment information. |

## Supported middlewares
All middlewares could be configured via YAML or Code.

**User can enable anyone of those as needed! No mandatory binding!**

| Middleware | Description |
| --- | --- |
| Metrics | Collect RPC metrics and export to [prometheus](https://github.com/prometheus/client_golang) client. |
| Log | Log every RPC requests as event with [rk-query](https://github.com/rookie-ninja/rk-query). |
| Trace | Collect RPC trace and export it to stdout, file or jaeger with [open-telemetry/opentelemetry-go](https://github.com/open-telemetry/opentelemetry-go). |
| Panic | Recover from panic for RPC requests and log it. |
| Meta | Send micsroservice metadata as header to client. |
| Auth | Support [Basic Auth] and [API Key] authorization types. |
| RateLimit | Limiting RPC rate globally or per path. |
| Timeout | Timing out request by configuration. |
| CORS | Server side CORS validation. |
| JWT | Server side JWT validation. |
| Secure | Server side secure validation. |
| CSRF | Server side csrf validation. |

## Installation
`go get github.com/rookie-ninja/rk-zero`

## Quick Start
In the bellow example, we will start microservice with bellow functionality and middlewares enabled via YAML.

- [zeromicro/go-zero](https://github.com/zeromicro/go-zero) server
- Swagger UI
- CommonService
- TV
- Prometheus Metrics (middleware)
- Logging (middleware)
- Meta (middleware)

Please refer example at [example/boot/simple](example/boot/simple).

### 1.Create boot.yaml
- [boot.yaml](example/boot/simple/boot.yaml)

```yaml
---
zero:
  - name: greeter                     # Required
    port: 8080                        # Required
    enabled: true                     # Required
    tv:
      enabled: true                   # Optional, default: false
    prom:
      enabled: true                   # Optional, default: false
    sw:
      enabled: true                   # Optional, default: false
    commonService:
      enabled: true                   # Optional, default: false
    interceptors:
      loggingZap:
        enabled: true                 # Optional, default: false
      metricsProm:
        enabled: true                 # Optional, default: false
      meta:
        enabled: true                 # Optional, default: false
```

### 2.Create main.go
- [main.go](example/boot/simple/main.go)

```go
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
		Path: "/v1/greeter",
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
```

### 3.Start server

```go
$ go run main.go
```

### 4.Validation
#### 4.1 GoZero server
Try to test GoZero Service with [curl](https://curl.se/)

```shell script
# Curl to common service
$ curl localhost:8080/rk/v1/healthy
{"healthy":true}
```

#### 4.2 Swagger UI
Please refer [documentation](https://rkdev.info/docs/bootstrapper/user-guide/zero-golang/basic/swagger-ui/) for details of configuration.

By default, we could access swagger UI at [http://localhost:8080/sw](http://localhost:8080/sw)

![sw](docs/img/simple-sw.png)

#### 4.3 TV
Please refer [documentation](https://rkdev.info/docs/bootstrapper/user-guide/zero-golang/basic/tv/) for details of configuration.

By default, we could access TV at [http://localhost:8080/rk/v1/tv](http://localhost:8080/rk/v1/tv)

#### 4.4 Prometheus Metrics
Please refer [documentation](https://rkdev.info/docs/bootstrapper/user-guide/zero-golang/basic/middleware-metrics/) for details of configuration.

By default, we could access prometheus client at [http://localhost:8080/metrics](http://localhost:8080/metrics)

![prom](docs/img/simple-prom.png)

#### 4.5 Logging
Please refer [documentation](https://rkdev.info/docs/bootstrapper/user-guide/zero-golang/basic/middleware-logging/) for details of configuration.

By default, we enable zap logger and event logger with encoding type of [console]. Encoding type of [json] is also supported.

```shell script
2021-12-29T01:47:33.795+0800    INFO    boot/zero_entry.go:1168 Bootstrap zeroEntry     {"eventId": "9b176423-d751-4066-838a-1eedcc72a7fb", "entryName": "greeter"}
------------------------------------------------------------------------
endTime=2021-12-29T01:47:33.797725+08:00
startTime=2021-12-29T01:47:33.795914+08:00
elapsedNano=1810699
timezone=CST
ids={"eventId":"9b176423-d751-4066-838a-1eedcc72a7fb"}
app={"appName":"rk","appVersion":"","entryName":"greeter","entryType":"ZeroEntry"}
env={"arch":"amd64","az":"*","domain":"*","hostname":"lark.local","localIP":"10.8.0.2","os":"darwin","realm":"*","region":"*"}
payloads={"commonServiceEnabled":true,"commonServicePathPrefix":"/rk/v1/","zeroPort":8080,"promEnabled":true,"promPath":"/metrics","promPort":8080,"swEnabled":true,"swPath":"/sw/","tvEnabled":true,"tvPath":"/rk/v1/tv/"}
error={}
counters={}
pairs={}
timing={}
remoteAddr=localhost
operation=Bootstrap
resCode=OK
eventStatus=Ended
EOE
```

#### 4.6 Meta
Please refer [documentation](https://rkdev.info/docs/bootstrapper/user-guide/zero-golang/basic/middleware-meta/) for details of configuration.

By default, we will send back some metadata to client including gateway with headers.

```shell script
$ curl -vs localhost:8080/rk/v1/healthy
...
< HTTP/1.1 200 OK
< Content-Type: application/json
< X-Request-Id: f068670c-56dc-42ed-9368-14961acd8433
< X-Rk-App-Name: rk
< X-Rk-App-Unix-Time: 2021-12-29T01:50:35.791623+08:00
< X-Rk-App-Version: 
< X-Rk-Received-Time: 2021-12-29T01:50:35.791623+08:00
< X-Trace-Id: 3a84ce72b53ce43468a5e81e8dceadcb
< Date: Tue, 28 Dec 2021 17:50:35 GMT
...
```

#### 4.7 Send request
We registered /v1/greeter API in [zeromicro/go-zero](https://github.com/zeromicro/go-zero) server and let's validate it!

```shell script
$ curl -vs localhost:8080/v1/greeter?
*   Trying ::1...
* TCP_NODELAY set
* Connected to localhost (::1) port 8080 (#0)
> GET /v1/greeter HTTP/1.1
> Host: localhost:8080
> User-Agent: curl/7.64.1
> Accept: */*
> 
< HTTP/1.1 200 OK
< X-Request-Id: 38bb7368-a829-4707-b079-a942ec4c1f82
< X-Rk-App-Name: rk
< X-Rk-App-Unix-Time: 2021-12-29T01:52:32.478754+08:00
< X-Rk-App-Version: 
< X-Rk-Received-Time: 2021-12-29T01:52:32.478754+08:00
< X-Trace-Id: 4170ff1daeb053166c26f0d7ca98c57e
< Date: Tue, 28 Dec 2021 17:52:32 GMT
< Content-Length: 6
< Content-Type: text/plain; charset=utf-8
< 
* Connection #0 to host localhost left intact
Hello!*
```

#### 4.8 RPC logs
Bellow logs would be printed in stdout.

```
------------------------------------------------------------------------
endTime=2021-12-29T01:52:32.478833+08:00
startTime=2021-12-29T01:52:32.478736+08:00
elapsedNano=96450
timezone=CST
ids={"eventId":"38bb7368-a829-4707-b079-a942ec4c1f82","requestId":"38bb7368-a829-4707-b079-a942ec4c1f82","traceId":"4170ff1daeb053166c26f0d7ca98c57e"}
app={"appName":"rk","appVersion":"","entryName":"greeter","entryType":"ZeroEntry"}
env={"arch":"amd64","az":"*","domain":"*","hostname":"lark.local","localIP":"10.8.0.2","os":"darwin","realm":"*","region":"*"}
payloads={"apiMethod":"GET","apiPath":"/v1/greeter","apiProtocol":"HTTP/1.1","apiQuery":"","userAgent":"curl/7.64.1"}
error={}
counters={}
pairs={}
timing={}
remoteAddr=localhost:62686
operation=/v1/greeter
resCode=200
eventStatus=Ended
EOE
```

#### 4.9 RPC prometheus metrics
Prometheus client will automatically register into [zeromicro/go-zero](https://github.com/zeromicro/go-zero) instance at /metrics.

Access [http://localhost:8080/metrics](http://localhost:8080/metrics)

![image](docs/img/prom-inter.png)

## YAML Options
User can start multiple [zeromicro/go-zero](https://github.com/zeromicro/go-zero) instances at the same time. Please make sure use different port and name.

### go-zero
| name | description | type | default value |
| ------ | ------ | ------ | ------ |
| zero.name | The name of zero server | string | N/A |
| zero.port | The port of zero server | integer | nil, server won't start |
| zero.enabled | Enable zero entry or not | bool | false |
| zero.description | Description of zero entry. | string | "" |
| zero.certEntry | Reference of cert entry declared in [cert entry](https://github.com/rookie-ninja/rk-entry#certentry) | string | "" |
| zero.logger.zapLogger | Reference of zapLoggerEntry declared in [zapLoggerEntry](https://github.com/rookie-ninja/rk-entry#zaploggerentry) | string | "" |
| zero.logger.eventLogger | Reference of eventLoggerEntry declared in [eventLoggerEntry](https://github.com/rookie-ninja/rk-entry#eventloggerentry) | string | "" |

### CommonService
| Path | Description |
| ---- | ---- |
| /rk/v1/certs | List CertEntry. |
| /rk/v1/configs | List ConfigEntry. |
| /rk/v1/deps | List dependencies related application, entire contents of go.mod file would be returned. |
| /rk/v1/entries | List all Entries. |
| /rk/v1/gc | Trigger GC |
| /rk/v1/healthy | Get application healthy status. |
| /rk/v1/info | Get application and process info. |
| /rk/v1/license | Get license related application, entire contents of LICENSE file would be returned. |
| /rk/v1/logs | List logger related entries. |
| /rk/v1/git | Get git information. |
| /rk/v1/readme | Get contents of README file. |
| /rk/v1/sys | Get OS stat. |
| /rk/v1/tv | Get HTML page of /tv. |

| name | description | type | default value |
| ------ | ------ | ------ | ------ |
| zero.commonService.enabled | Enable embedded common service | boolean | false |

### Swagger
| name | description | type | default value |
| ------ | ------ | ------ | ------ |
| zero.sw.enabled | Enable swagger service over zero server | boolean | false |
| zero.sw.path | The path access swagger service from web | string | /sw |
| zero.sw.jsonPath | Where the swagger.json files are stored locally | string | "" |
| zero.sw.headers | Headers would be sent to caller as scheme of [key:value] | []string | [] |

### Prometheus Client
| name | description | type | default value |
| ------ | ------ | ------ | ------ |
| zero.prom.enabled | Enable prometheus | boolean | false |
| zero.prom.path | Path of prometheus | string | /metrics |
| zero.prom.pusher.enabled | Enable prometheus pusher | bool | false |
| zero.prom.pusher.jobName | Job name would be attached as label while pushing to remote pushgateway | string | "" |
| zero.prom.pusher.remoteAddress | PushGateWay address, could be form of http://x.x.x.x or x.x.x.x | string | "" |
| zero.prom.pusher.intervalMs | Push interval in milliseconds | string | 1000 |
| zero.prom.pusher.basicAuth | Basic auth used to interact with remote pushgateway, form of [user:pass] | string | "" |
| zero.prom.pusher.cert.ref | Reference of rkentry.CertEntry | string | "" |

### TV
| name | description | type | default value |
| ------ | ------ | ------ | ------ |
| zero.tv.enabled | Enable RK TV | boolean | false |

### Middlewares
#### Log
| name | description | type | default value |
| ------ | ------ | ------ | ------ |
| zero.interceptors.loggingZap.enabled | Enable log interceptor | boolean | false |
| zero.interceptors.loggingZap.zapLoggerEncoding | json or console | string | console |
| zero.interceptors.loggingZap.zapLoggerOutputPaths | Output paths | []string | stdout |
| zero.interceptors.loggingZap.eventLoggerEncoding | json or console | string | console |
| zero.interceptors.loggingZap.eventLoggerOutputPaths | Output paths | []string | false |

We will log two types of log for every RPC call.
- zapLogger

Contains user printed logging with requestId or traceId.

- eventLogger

Contains per RPC metadata, response information, environment information and etc.

| Field | Description |
| ---- | ---- |
| endTime | As name described |
| startTime | As name described |
| elapsedNano | Elapsed time for RPC in nanoseconds |
| timezone | As name described |
| ids | Contains three different ids(eventId, requestId and traceId). If meta interceptor was enabled or event.SetRequestId() was called by user, then requestId would be attached. eventId would be the same as requestId if meta interceptor was enabled. If trace interceptor was enabled, then traceId would be attached. |
| app | Contains [appName, appVersion](https://github.com/rookie-ninja/rk-entry#appinfoentry), entryName, entryType. |
| env | Contains arch, az, domain, hostname, localIP, os, realm, region. realm, region, az, domain were retrieved from environment variable named as REALM, REGION, AZ and DOMAIN. "*" means empty environment variable.|
| payloads | Contains RPC related metadata |
| error | Contains errors if occur |
| counters | Set by calling event.SetCounter() by user. |
| pairs | Set by calling event.AddPair() by user. |
| timing | Set by calling event.StartTimer() and event.EndTimer() by user. |
| remoteAddr |  As name described |
| operation | RPC method name |
| resCode | Response code of RPC |
| eventStatus | Ended or InProgress |

- example

```shell script
------------------------------------------------------------------------
endTime=2021-11-01T23:31:01.706614+08:00
startTime=2021-11-01T23:31:01.706335+08:00
elapsedNano=278966
timezone=CST
ids={"eventId":"61cae46e-ea98-47b5-8a39-1090d015e09a","requestId":"61cae46e-ea98-47b5-8a39-1090d015e09a"}
app={"appName":"rk-zero","appVersion":"master-e4538d7","entryName":"greeter","entryType":"ZeroEntry"}
env={"arch":"amd64","az":"*","domain":"*","hostname":"lark.local","localIP":"192.168.1.104","os":"darwin","realm":"*","region":"*"}
payloads={"apiMethod":"GET","apiPath":"/rk/v1/healthy","apiProtocol":"HTTP/1.1","apiQuery":"","userAgent":"curl/7.64.1"}
error={}
counters={}
pairs={}
timing={}
remoteAddr=localhost:54376
operation=/rk/v1/healthy
resCode=200
eventStatus=Ended
EOE
```

#### Metrics
| name | description | type | default value |
| ------ | ------ | ------ | ------ |
| zero.interceptors.metricsProm.enabled | Enable metrics interceptor | boolean | false |

#### Auth
Enable the server side auth. codes.Unauthenticated would be returned to client if not authorized with user defined credential.

| name | description | type | default value |
| ------ | ------ | ------ | ------ |
| zero.interceptors.auth.enabled | Enable auth interceptor | boolean | false |
| zero.interceptors.auth.basic | Basic auth credentials as scheme of <user:pass> | []string | [] |
| zero.interceptors.auth.apiKey | API key auth | []string | [] |
| zero.interceptors.auth.ignorePrefix | The paths of prefix that will be ignored by interceptor | []string | [] |

#### Meta
Send application metadata as header to client.

| name | description | type | default value |
| ------ | ------ | ------ | ------ |
| zero.interceptors.meta.enabled | Enable meta interceptor | boolean | false |
| zero.interceptors.meta.prefix | Header key was formed as X-<Prefix>-XXX | string | RK |

#### Tracing
| name | description | type | default value |
| ------ | ------ | ------ | ------ |
| zero.interceptors.tracingTelemetry.enabled | Enable tracing interceptor | boolean | false |
| zero.interceptors.tracingTelemetry.exporter.file.enabled | Enable file exporter | boolean | RK |
| zero.interceptors.tracingTelemetry.exporter.file.outputPath | Export tracing info to files | string | stdout |
| zero.interceptors.tracingTelemetry.exporter.jaeger.agent.enabled | Export tracing info to jaeger agent | boolean | false |
| zero.interceptors.tracingTelemetry.exporter.jaeger.agent.host | As name described | string | localhost |
| zero.interceptors.tracingTelemetry.exporter.jaeger.agent.port | As name described | int | 6831 |
| zero.interceptors.tracingTelemetry.exporter.jaeger.collector.enabled | Export tracing info to jaeger collector | boolean | false |
| zero.interceptors.tracingTelemetry.exporter.jaeger.collector.endpoint | As name described | string | http://localhost:16368/api/trace |
| zero.interceptors.tracingTelemetry.exporter.jaeger.collector.username | As name described | string | "" |
| zero.interceptors.tracingTelemetry.exporter.jaeger.collector.password | As name described | string | "" |

#### RateLimit
| name | description | type | default value |
| ------ | ------ | ------ | ------ |
| zero.interceptors.rateLimit.enabled | Enable rate limit interceptor | boolean | false |
| zero.interceptors.rateLimit.algorithm | Provide algorithm, tokenBucket and leakyBucket are available options | string | tokenBucket |
| zero.interceptors.rateLimit.reqPerSec | Request per second globally | int | 0 |
| zero.interceptors.rateLimit.paths.path | Full path | string | "" |
| zero.interceptors.rateLimit.paths.reqPerSec | Request per second by full path | int | 0 |

#### Timeout
| name | description | type | default value |
| ------ | ------ | ------ | ------ |
| zero.interceptors.timeout.enabled | Enable timeout interceptor | boolean | false |
| zero.interceptors.timeout.timeoutMs | Global timeout in milliseconds. | int | 5000 |
| zero.interceptors.timeout.paths.path | Full path | string | "" |
| zero.interceptors.timeout.paths.timeoutMs | Timeout in milliseconds by full path | int | 5000 |

#### CORS
| name | description | type | default value |
| ------ | ------ | ------ | ------ |
| zero.interceptors.cors.enabled | Enable cors interceptor | boolean | false |
| zero.interceptors.cors.allowOrigins | Provide allowed origins with wildcard enabled. | []string | * |
| zero.interceptors.cors.allowMethods | Provide allowed methods returns as response header of OPTIONS request. | []string | All http methods |
| zero.interceptors.cors.allowHeaders | Provide allowed headers returns as response header of OPTIONS request. | []string | Headers from request |
| zero.interceptors.cors.allowCredentials | Returns as response header of OPTIONS request. | bool | false |
| zero.interceptors.cors.exposeHeaders | Provide exposed headers returns as response header of OPTIONS request. | []string | "" |
| zero.interceptors.cors.maxAge | Provide max age returns as response header of OPTIONS request. | int | 0 |

#### JWT
In order to make swagger UI and RK tv work under JWT without JWT token, we need to ignore prefixes of paths as bellow.

```yaml
jwt:
  ...
  ignorePrefix:
   - "/rk/v1/tv"
   - "/sw"
   - "/rk/v1/assets"
```

| name | description | type | default value |
| ------ | ------ | ------ | ------ |
| zero.interceptors.jwt.enabled | Enable JWT interceptor | boolean | false |
| zero.interceptors.jwt.signingKey | Required, Provide signing key. | string | "" |
| zero.interceptors.jwt.ignorePrefix | Provide ignoring path prefix. | []string | [] |
| zero.interceptors.jwt.signingKeys | Provide signing keys as scheme of <key>:<value>. | []string | [] |
| zero.interceptors.jwt.signingAlgo | Provide signing algorithm. | string | HS256 |
| zero.interceptors.jwt.tokenLookup | Provide token lookup scheme, please see bellow description. | string | "header:Authorization" |
| zero.interceptors.jwt.authScheme | Provide auth scheme. | string | Bearer |

The supported scheme of **tokenLookup** 

```
// Optional. Default value "header:Authorization".
// Possible values:
// - "header:<name>"
// - "query:<name>"
// - "param:<name>"
// - "cookie:<name>"
// - "form:<name>"
// Multiply sources example:
// - "header: Authorization,cookie: myowncookie"
```

#### Secure
| name | description | type | default value |
| ------ | ------ | ------ | ------ |
| zero.interceptors.secure.enabled | Enable secure interceptor | boolean | false |
| zero.interceptors.secure.xssProtection | X-XSS-Protection header value. | string | "1; mode=block" |
| zero.interceptors.secure.contentTypeNosniff | X-Content-Type-Options header value. | string | nosniff |
| zero.interceptors.secure.xFrameOptions | X-Frame-Options header value. | string | SAMEORIGIN |
| zero.interceptors.secure.hstsMaxAge | Strict-Transport-Security header value. | int | 0 |
| zero.interceptors.secure.hstsExcludeSubdomains | Excluding subdomains of HSTS. | bool | false |
| zero.interceptors.secure.hstsPreloadEnabled | Enabling HSTS preload. | bool | false |
| zero.interceptors.secure.contentSecurityPolicy | Content-Security-Policy header value. | string | "" |
| zero.interceptors.secure.cspReportOnly | Content-Security-Policy-Report-Only header value. | bool | false |
| zero.interceptors.secure.referrerPolicy | Referrer-Policy header value. | string | "" |
| zero.interceptors.secure.ignorePrefix | Ignoring path prefix. | []string | [] |

#### CSRF
| name | description | type | default value |
| ------ | ------ | ------ | ------ |
| zero.interceptors.csrf.enabled | Enable csrf interceptor | boolean | false |
| zero.interceptors.csrf.tokenLength | Provide the length of the generated token. | int | 32 |
| zero.interceptors.csrf.tokenLookup | Provide csrf token lookup rules, please see code comments for details. | string | "header:X-CSRF-Token" |
| zero.interceptors.csrf.cookieName | Provide name of the CSRF cookie. This cookie will store CSRF token. | string | _csrf |
| zero.interceptors.csrf.cookieDomain | Domain of the CSRF cookie. | string | "" |
| zero.interceptors.csrf.cookiePath | Path of the CSRF cookie. | string | "" |
| zero.interceptors.csrf.cookieMaxAge | Provide max age (in seconds) of the CSRF cookie. | int | 86400 |
| zero.interceptors.csrf.cookieHttpOnly | Indicates if CSRF cookie is HTTP only. | bool | false |
| zero.interceptors.csrf.cookieSameSite | Indicates SameSite mode of the CSRF cookie. Options: lax, strict, none, default | string | default |
| zero.interceptors.csrf.ignorePrefix | Ignoring path prefix. | []string | [] |

### Full YAML
```yaml
---
#app:
#  description: "this is description"                      # Optional, default: ""
#  keywords: ["rk", "golang"]                              # Optional, default: []
#  homeUrl: "http://example.com"                           # Optional, default: ""
#  iconUrl: "http://example.com"                           # Optional, default: ""
#  docsUrl: ["http://example.com"]                         # Optional, default: []
#  maintainers: ["rk-dev"]                                 # Optional, default: []
#zapLogger:
#  - name: zap-logger                                      # Required
#    description: "Description of entry"                   # Optional
#    loki:
#      enabled: true                                       # Optional, default: false
#      addr: localhost:3100                                # Optional, default: localhost:3100
#      path: /loki/api/v1/push                             # Optional, default: /loki/api/v1/push
#      username: ""                                        # Optional, default: ""
#      password: ""                                        # Optional, default: ""
#      maxBatchWaitMs: 3000                                # Optional, default: 3000
#      maxBatchSize: 1000                                  # Optional, default: 1000
#      insecureSkipVerify: false                           # Optional, default: false
#      labels:                                             # Optional, default: empty map
#        my_label_key: my_label_value
#eventLogger:
#  - name: event-logger                                    # Required
#    description: "Description of entry"                   # Optional
#    loki:
#      enabled: true                                       # Optional, default: false
#      addr: localhost:3100                                # Optional, default: localhost:3100
#      path: /loki/api/v1/push                             # Optional, default: /loki/api/v1/push
#      username: ""                                        # Optional, default: ""
#      password: ""                                        # Optional, default: ""
#      maxBatchWaitMs: 3000                                # Optional, default: 3000
#      maxBatchSize: 1000                                  # Optional, default: 1000
#      insecureSkipVerify: false                           # Optional, default: false
#      labels:                                             # Optional, default: empty map
#        my_label_key: my_label_value
#cred:
#  - name: "local-cred"                                    # Required
#    provider: "localFs"                                   # Required, etcd, consul, localFs, remoteFs are supported options
#    description: "Description of entry"                   # Optional
#    locale: "*::*::*::*"                                  # Optional, default: *::*::*::*
#    paths:                                                # Optional
#      - "example/boot/full/cred.yaml"
#cert:
#  - name: "local-cert"                                    # Required
#    provider: "localFs"                                   # Required, etcd, consul, localFs, remoteFs are supported options
#    description: "Description of entry"                   # Optional
#    locale: "*::*::*::*"                                  # Optional, default: *::*::*::*
#    serverCertPath: "example/boot/full/server.pem"        # Optional, default: "", path of certificate on local FS
#    serverKeyPath: "example/boot/full/server-key.pem"     # Optional, default: "", path of certificate on local FS
#    clientCertPath: "example/client.pem"                  # Optional, default: "", path of certificate on local FS
#    clientKeyPath: "example/client.pem"                   # Optional, default: "", path of certificate on local FS
#config:
#  - name: rk-main                                         # Required
#    path: "example/boot/full/config.yaml"                 # Required
#    locale: "*::*::*::*"                                  # Required, default: *::*::*::*
#    description: "Description of entry"                   # Optional
zero:
  - name: greeter                                          # Required
    port: 8080                                             # Required
    enabled: true                                          # Required
#    description: "greeter server"                         # Optional, default: ""
#    certEntry: "local-cert"                               # Optional, default: "", reference of cert entry declared above
#    sw:
#      enabled: true                                       # Optional, default: false
#      path: "sw"                                          # Optional, default: "sw"
#      jsonPath: ""                                        # Optional
#      headers: ["sw:rk"]                                  # Optional, default: []
#    commonService:
#      enabled: true                                       # Optional, default: false
#    tv:
#      enabled:  true                                      # Optional, default: false
#    prom:
#      enabled: true                                       # Optional, default: false
#      path: ""                                            # Optional, default: "metrics"
#      pusher:
#        enabled: false                                    # Optional, default: false
#        jobName: "greeter-pusher"                         # Required
#        remoteAddress: "localhost:9091"                   # Required
#        basicAuth: "user:pass"                            # Optional, default: ""
#        intervalMs: 10000                                 # Optional, default: 1000
#        cert:                                             # Optional
#          ref: "local-test"                               # Optional, default: "", reference of cert entry declared above
#    logger:
#      zapLogger: zap-logger                               # Optional, default: logger of STDOUT, reference of logger entry declared above
#      eventLogger: event-logger                           # Optional, default: logger of STDOUT, reference of logger entry declared above
#    interceptors:
#      loggingZap:
#        enabled: true                                     # Optional, default: false
#        zapLoggerEncoding: "json"                         # Optional, default: "console"
#        zapLoggerOutputPaths: ["logs/app.log"]            # Optional, default: ["stdout"]
#        eventLoggerEncoding: "json"                       # Optional, default: "console"
#        eventLoggerOutputPaths: ["logs/event.log"]        # Optional, default: ["stdout"]
#      metricsProm:
#        enabled: true                                     # Optional, default: false
#      auth:
#        enabled: true                                     # Optional, default: false
#        basic:
#          - "user:pass"                                   # Optional, default: []
#        ignorePrefix:
#          - "/rk/v1"                                      # Optional, default: []
#        apiKey:
#          - "keys"                                        # Optional, default: []
#      meta:
#        enabled: true                                     # Optional, default: false
#        prefix: "rk"                                      # Optional, default: "rk"
#      tracingTelemetry:
#        enabled: true                                     # Optional, default: false
#        exporter:                                         # Optional, default will create a stdout exporter
#          file:
#            enabled: true                                 # Optional, default: false
#            outputPath: "logs/trace.log"                  # Optional, default: stdout
#          jaeger:
#            agent:
#              enabled: false                              # Optional, default: false
#              host: ""                                    # Optional, default: localhost
#              port: 0                                     # Optional, default: 6831
#            collector:
#              enabled: true                               # Optional, default: false
#              endpoint: ""                                # Optional, default: http://localhost:14268/api/traces
#              username: ""                                # Optional, default: ""
#              password: ""                                # Optional, default: ""
#      rateLimit:
#        enabled: false                                    # Optional, default: false
#        algorithm: "leakyBucket"                          # Optional, default: "tokenBucket"
#        reqPerSec: 100                                    # Optional, default: 1000000
#        paths:
#          - path: "/rk/v1/healthy"                        # Optional, default: ""
#            reqPerSec: 0                                  # Optional, default: 1000000
#      timeout:
#        enabled: false                                    # Optional, default: false
#        timeoutMs: 5000                                   # Optional, default: 5000
#        paths:
#          - path: "/rk/v1/healthy"                        # Optional, default: ""
#            timeoutMs: 1000                               # Optional, default: 5000
#      jwt:
#        enabled: true                                     # Optional, default: false
#        signingKey: "my-secret"                           # Required
#        ignorePrefix:                                     # Optional, default: []
#          - "/rk/v1/tv"
#          - "/sw"
#          - "/rk/v1/assets"
#        signingKeys:                                      # Optional
#          - "key:value"
#        signingAlgo: ""                                   # Optional, default: "HS256"
#        tokenLookup: "header:<name>"                      # Optional, default: "header:Authorization"
#        authScheme: "Bearer"                              # Optional, default: "Bearer"
#      secure:
#        enabled: true                                     # Optional, default: false
#        xssProtection: ""                                 # Optional, default: "1; mode=block"
#        contentTypeNosniff: ""                            # Optional, default: nosniff
#        xFrameOptions: ""                                 # Optional, default: SAMEORIGIN
#        hstsMaxAge: 0                                     # Optional, default: 0
#        hstsExcludeSubdomains: false                      # Optional, default: false
#        hstsPreloadEnabled: false                         # Optional, default: false
#        contentSecurityPolicy: ""                         # Optional, default: ""
#        cspReportOnly: false                              # Optional, default: false
#        referrerPolicy: ""                                # Optional, default: ""
#        ignorePrefix: []                                  # Optional, default: []
#      csrf:
#        enabled: true
#        tokenLength: 32                                   # Optional, default: 32
#        tokenLookup: "header:X-CSRF-Token"                # Optional, default: "header:X-CSRF-Token"
#        cookieName: "_csrf"                               # Optional, default: _csrf
#        cookieDomain: ""                                  # Optional, default: ""
#        cookiePath: ""                                    # Optional, default: ""
#        cookieMaxAge: 86400                               # Optional, default: 86400
#        cookieHttpOnly: false                             # Optional, default: false
#        cookieSameSite: "default"                         # Optional, default: "default", options: lax, strict, none, default
#        ignorePrefix: []                                  # Optional, default: []
```

## Development Status: Testing

## Build instruction
Simply run make all to validate your changes. Or run codes in example/ folder.

- make all

Run unit-test, golangci-lint, doctoc and gofmt.

## Test instruction
Run unit test with **make test** command.

github workflow will automatically run unit test and golangci-lint for testing and lint validation.

## Contributing
We encourage and support an active, healthy community of contributors &mdash;
including you! Details are in the [contribution guide](CONTRIBUTING.md) and
the [code of conduct](CODE_OF_CONDUCT.md). The rk maintainers keep an eye on
issues and pull requests, but you can also report any negative conduct to
lark@rkdev.info.

Released under the [Apache 2.0 License](LICENSE).

