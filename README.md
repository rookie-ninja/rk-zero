# rk-zero
[![build](https://github.com/rookie-ninja/rk-zero/actions/workflows/ci.yml/badge.svg)](https://github.com/rookie-ninja/rk-zero/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/rookie-ninja/rk-zero/branch/master/graph/badge.svg?token=Y1HM9UQBX6)](https://codecov.io/gh/rookie-ninja/rk-zero)
[![Go Report Card](https://goreportcard.com/badge/github.com/rookie-ninja/rk-zero)](https://goreportcard.com/report/github.com/rookie-ninja/rk-zero)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Middleware & bootstrapper designed for [zeromicro/go-zero](https://github.com/zeromicro/go-zero) framework.  [Documentation](https://docs.rkdev.info/docs/rk-boot/getting-started/zero/).

This belongs to [rk-boot](https://github.com/rookie-ninja/rk-boot) family. 

![image](docs/img/boot-arch.png)

## Architecture
![image](docs/img/zero-arch.png)

## Supported bootstrap
| Bootstrap  | Description                                                                            |
|------------|----------------------------------------------------------------------------------------|
| YAML based | Start [zeromicro/go-zero](https://github.com/zeromicro/go-zero) microservice from YAML |
| Code based | Start [zeromicro/go-zero](https://github.com/zeromicro/go-zero) microservice from code |

## Supported instances
All instances could be configured via YAML or Code.

**User can enable anyone of those as needed! No mandatory binding!**

| Instance          | Description                                                                                                   |
|-------------------|---------------------------------------------------------------------------------------------------------------|
| rest.Server       | Compatible with original [zeromicro/go-zero](https://github.com/zeromicro/go-zero) service functionalities    |
| Config            | Configure [spf13/viper](https://github.com/spf13/viper) as config instance and reference it from YAML         |
| Logger            | Configure [uber-go/zap](https://github.com/uber-go/zap) logger configuration and reference it from YAML       |
| Event             | Configure logging of RPC with [rk-query](https://github.com/rookie-ninja/rk-query) and reference it from YAML |
| Cert              | Fetch TLS/SSL certificates start microservice.                                                                |
| Prometheus        | Start prometheus client at client side and push metrics to pushgateway as needed.                             |
| Swagger           | Builtin swagger UI handler.                                                                                   |
| Docs              | Builtin [RapiDoc](https://github.com/mrin9/RapiDoc) instance which can be used to replace swagger and RK TV.  |
| CommonService     | List of common APIs.                                                                                          |
| StaticFileHandler | A Web UI shows files could be downloaded from server, currently support source of local and embed.FS.         |
| PProf             | PProf web UI.                                                                                                 |


## Supported middlewares
All middlewares could be configured via YAML or Code.

**User can enable anyone of those as needed! No mandatory binding!**

| Middleware | Description                                                                                                                                           |
|------------|-------------------------------------------------------------------------------------------------------------------------------------------------------|
| Prom       | Collect RPC metrics and export to [prometheus](https://github.com/prometheus/client_golang) client.                                                   |
| Logging    | Log every RPC requests as event with [rk-query](https://github.com/rookie-ninja/rk-query).                                                            |
| Trace      | Collect RPC trace and export it to stdout, file or jaeger with [open-telemetry/opentelemetry-go](https://github.com/open-telemetry/opentelemetry-go). |
| Panic      | Recover from panic for RPC requests and log it.                                                                                                       |
| Meta       | Send micsro service metadata as header to client.                                                                                                     |
| Auth       | Support [Basic Auth] and [API Key] authorization types.                                                                                               |
| RateLimit  | Limiting RPC rate globally or per path.                                                                                                               |
| CORS       | Server side CORS validation.                                                                                                                          |
| JWT        | Server side JWT validation.                                                                                                                           |
| Secure     | Server side secure validation.                                                                                                                        |
| CSRF       | Server side csrf validation.                                                                                                                          |


## Installation
`go get github.com/rookie-ninja/rk-zero`

## Quick Start
In the bellow example, we will start microservice with bellow functionality and middlewares enabled via YAML.

- [zeromicro/go-zero](https://github.com/zeromicro/go-zero) server
- Swagger UI
- CommonService
- Docs
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
    commonService:
      enabled: true                   # Optional, default: false
    sw:
      enabled: true                   # Optional, default: false
    docs:
      enabled: true                   # Optional, default: false
    prom:
      enabled: true                   # Optional, default: false
    middleware:
      logging:
        enabled: true                 # Optional, default: false
      prom:
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
	_ "embed"
	"encoding/json"
	"fmt"
	"github.com/rookie-ninja/rk-entry/v2/entry"
	"github.com/rookie-ninja/rk-zero/boot"
	"github.com/zeromicro/go-zero/rest"
	"net/http"
)

//go:embed boot.yaml
var boot []byte

func main() {
	// Bootstrap preload entries
	rkentry.BootstrapPreloadEntryYAML(boot)

	// Bootstrap zero entry from boot config
	res := rkzero.RegisterZeroEntryYAML(boot)

	// Get ZeroEntry
	zeroEntry := res["greeter"].(*rkzero.ZeroEntry)
	// Add router
	zeroEntry.Server.AddRoute(rest.Route{
		Method:  http.MethodGet,
		Path:    "/v1/greeter",
		Handler: Greeter,
	})

	// Bootstrap zero entry
	zeroEntry.Bootstrap(context.Background())

	// Wait for shutdown signal
	rkentry.GlobalAppCtx.WaitForShutdownSig()

	// Interrupt zero entry
	zeroEntry.Interrupt(context.Background())
}

func Greeter(writer http.ResponseWriter, request *http.Request) {
	writer.WriteHeader(http.StatusOK)
	resp := &GreeterResponse{
		Message: fmt.Sprintf("Hello %s!", request.URL.Query().Get("name")),
	}
	bytes, _ := json.Marshal(resp)
	writer.Write(bytes)
}

type GreeterResponse struct {
	Message string
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
$ curl localhost:8080/rk/v1/ready
{
  "ready": true
}

$ curl localhost:8080/rk/v1/alive
{
  "alive": true
}
```

#### 4.2 Swagger UI
Please refer **sw** section at [Full YAML](#full-yaml).

By default, we could access swagger UI at [http://localhost:8080/sw](http://localhost:8080/sw)

![sw](docs/img/simple-sw.png)

#### 4.3 Docs UI
Please refer **docs** section at [Full YAML](#full-yaml).

By default, we could access docs UI at [http://localhost:8080/docs](http://localhost:8080/docs)

![docs](docs/img/simple-docs.png)

#### 4.4 Prometheus Metrics
Please refer **middleware.prom** section at [Full YAML](#full-yaml).

By default, we could access prometheus client at [http://localhost:8080/metrics](http://localhost:8080/metrics)
- http://localhost:8080/metrics

![prom](docs/img/simple-prom.png)

#### 4.5 Logging
Please refer **middleware.logging** section at [Full YAML](#full-yaml).

By default, we enable zap logger and event logger with encoding type of [console]. Encoding type of [json] and [flatten] is also supported.

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
Please refer **meta** section at [Full YAML](#full-yaml).

By default, we will send back some metadata to client including gateway with headers.

```shell script
$ curl -vs localhost:8080/rk/v1/ready
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
$ curl -vs localhost:8080/v1/greeter?name=rk-dev
*   Trying ::1...
* TCP_NODELAY set
* Connected to localhost (::1) port 8080 (#0)
> GET /v1/greeter?name=rk-dev HTTP/1.1
> Host: localhost:8080
> User-Agent: curl/7.64.1
> Accept: */*
> 
< HTTP/1.1 200 OK
< X-Request-Id: d7a6e873-cf8e-465f-8248-c53a76831fed
< X-Rk-App-Locale: *::*::*::*
< X-Rk-App-Name: 
< X-Rk-App-Unix-Time: 2022-03-06T22:14:14.56221+08:00
< X-Rk-App-Version: 
< X-Rk-Received-Time: 2022-03-06T22:14:14.56221+08:00
< X-Trace-Id: 677c1314e24765ecc1e8ee7396f74d4e
< Date: Sun, 06 Mar 2022 14:14:14 GMT
< Content-Length: 27
< Content-Type: text/plain; charset=utf-8
< 
* Connection #0 to host localhost left intact
{"Message":"Hello rk-dev!"}
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
| name             | description                                                                                                        | type    | default value           |
|------------------|--------------------------------------------------------------------------------------------------------------------|---------|-------------------------|
| zero.name        | The name of zero server                                                                                            | string  | N/A                     |
| zero.port        | The port of zero server                                                                                            | integer | nil, server won't start |
| zero.enabled     | Enable zero entry or not                                                                                           | bool    | false                   |
| zero.description | Description of zero entry.                                                                                         | string  | ""                      |
| zero.certEntry   | Optional, Reference of certEntry declared in [cert entry](https://github.com/rookie-ninja/rk-entry#certentry)      | string  | ""                      |
| zero.loggerEntry | Optional, Reference of loggerEntry declared in [LoggerEntry](https://github.com/rookie-ninja/rk-entry#loggerentry) | string  | ""                      |
| zero.eventEntry  | Optional, Reference of eventLEntry declared in [eventEntry](https://github.com/rookie-ninja/rk-entry#evententry)   | string  | ""                      |

### CommonService
| Path         | Description                       |
|--------------|-----------------------------------|
| /rk/v1/gc    | Trigger GC                        |
| /rk/v1/ready | Get application readiness status. |
| /rk/v1/alive | Get application aliveness status. |
| /rk/v1/info  | Get application and process info. |

| name                          | description                             | type    | default value |
|-------------------------------|-----------------------------------------|---------|---------------|
| zero.commonService.enabled    | Optional, Enable builtin common service | boolean | false         |
| zero.commonService.pathPrefix | Optional, Provide path prefix           | string  | /rk/v1        |

### Swagger
| name             | description                                                        | type     | default value |
|------------------|--------------------------------------------------------------------|----------|---------------|
| zero.sw.enabled  | Optional, Enable swagger service over gin server                   | boolean  | false         |
| zero.sw.path     | Optional, The path access swagger service from web                 | string   | /sw           |
| zero.sw.jsonPath | Optional, Where the swagger.json files are stored locally          | []string | [""]          |
| zero.sw.headers  | Optional, Headers would be sent to caller as scheme of [key:value] | []string | []            |

### Docs (RapiDoc)
| name                  | description                                                                            | type     | default value |
|-----------------------|----------------------------------------------------------------------------------------|----------|---------------|
| zero.docs.enabled     | Optional, Enable RapiDoc service over gin server                                       | boolean  | false         |
| zero.docs.path        | Optional, The path access docs service from web                                        | string   | /docs         |
| zero.docs.jsonPath    | Optional, Where the swagger.json or open API files are stored locally                  | []string | [""]          |
| zero.docs.headers     | Optional, Headers would be sent to caller as scheme of [key:value]                     | []string | []            |
| zero.docs.style.theme | Optional, light and dark are supported options                                         | string   | []            |
| zero.docs.debug       | Optional, Enable debugging mode in RapiDoc which can be used as the same as Swagger UI | boolean  | false         |

### Prometheus Client
| name                           | description                                                                        | type    | default value |
|--------------------------------|------------------------------------------------------------------------------------|---------|---------------|
| zero.prom.enabled              | Optional, Enable prometheus                                                        | boolean | false         |
| zero.prom.path                 | Optional, Path of prometheus                                                       | string  | /metrics      |
| zero.prom.pusher.enabled       | Optional, Enable prometheus pusher                                                 | bool    | false         |
| zero.prom.pusher.jobName       | Optional, Job name would be attached as label while pushing to remote pushgateway  | string  | ""            |
| zero.prom.pusher.remoteAddress | Optional, PushGateWay address, could be form of http://x.x.x.x or x.x.x.x          | string  | ""            |
| zero.prom.pusher.intervalMs    | Optional, Push interval in milliseconds                                            | string  | 1000          |
| zero.prom.pusher.basicAuth     | Optional, Basic auth used to interact with remote pushgateway, form of [user:pass] | string  | ""            |
| zero.prom.pusher.certEntry     | Optional, Reference of rkentry.CertEntry                                           | string  | ""            |

### Static file handler
| name                   | description                                | type    | default value |
|------------------------|--------------------------------------------|---------|---------------|
| zero.static.enabled    | Optional, Enable static file handler       | boolean | false         |
| zero.static.path       | Optional, path of static file handler      | string  | /static       |
| zero.static.sourceType | Required, local and embed.FS are supported | string  | ""            |
| zero.static.sourcePath | Required, full path of source directory    | string  | ""            |

- About embed.FS
  User has to set embedFS before Bootstrap() function as bellow:
-
```go
//go:embed /*
var staticFS embed.FS

rkentry.GlobalAppCtx.AddEmbedFS(rkentry.StaticFileHandlerEntryType, "greeter", &staticFS)
```

### Middlewares
| name                   | description                                            | type     | default value |
|------------------------|--------------------------------------------------------|----------|---------------|
| zero.middleware.ignore | The paths of prefix that will be ignored by middleware | []string | []            |

#### Logging
| name                                      | description                                            | type     | default value |
|-------------------------------------------|--------------------------------------------------------|----------|---------------|
| zero.middleware.logging.enabled           | Enable log middleware                                  | boolean  | false         |
| zero.middleware.logging.ignore            | The paths of prefix that will be ignored by middleware | []string | []            |
| zero.middleware.logging.loggerEncoding    | json or console or flatten                             | string   | console       |
| zero.middleware.logging.loggerOutputPaths | Output paths                                           | []string | stdout        |
| zero.middleware.logging.eventEncoding     | json or console or flatten                             | string   | console       |
| zero.middleware.logging.eventOutputPaths  | Output paths                                           | []string | false         |

We will log two types of log for every RPC call.
- Logger

Contains user printed logging with requestId or traceId.

- Event

Contains per RPC metadata, response information, environment information and etc.

| Field       | Description                                                                                                                                                                                                                                                                                                           |
|-------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| endTime     | As name described                                                                                                                                                                                                                                                                                                     |
| startTime   | As name described                                                                                                                                                                                                                                                                                                     |
| elapsedNano | Elapsed time for RPC in nanoseconds                                                                                                                                                                                                                                                                                   |
| timezone    | As name described                                                                                                                                                                                                                                                                                                     |
| ids         | Contains three different ids(eventId, requestId and traceId). If meta interceptor was enabled or event.SetRequestId() was called by user, then requestId would be attached. eventId would be the same as requestId if meta interceptor was enabled. If trace interceptor was enabled, then traceId would be attached. |
| app         | Contains [appName, appVersion](https://github.com/rookie-ninja/rk-entry#appinfoentry), entryName, entryType.                                                                                                                                                                                                          |
| env         | Contains arch, az, domain, hostname, localIP, os, realm, region. realm, region, az, domain were retrieved from environment variable named as REALM, REGION, AZ and DOMAIN. "*" means empty environment variable.                                                                                                      |
| payloads    | Contains RPC related metadata                                                                                                                                                                                                                                                                                         |
| error       | Contains errors if occur                                                                                                                                                                                                                                                                                              |
| counters    | Set by calling event.SetCounter() by user.                                                                                                                                                                                                                                                                            |
| pairs       | Set by calling event.AddPair() by user.                                                                                                                                                                                                                                                                               |
| timing      | Set by calling event.StartTimer() and event.EndTimer() by user.                                                                                                                                                                                                                                                       |
| remoteAddr  | As name described                                                                                                                                                                                                                                                                                                     |
| operation   | RPC method name                                                                                                                                                                                                                                                                                                       |
| resCode     | Response code of RPC                                                                                                                                                                                                                                                                                                  |
| eventStatus | Ended or InProgress                                                                                                                                                                                                                                                                                                   |

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

#### Prometheus
| name                         | description                                            | type     | default value |
|------------------------------|--------------------------------------------------------|----------|---------------|
| zero.middleware.prom.enabled | Enable metrics middleware                              | boolean  | false         |
| zero.middleware.prom.ignore  | The paths of prefix that will be ignored by middleware | []string | []            |

#### Auth
Enable the server side auth. codes.Unauthenticated would be returned to client if not authorized with user defined credential.

| name                         | description                                            | type     | default value |
|------------------------------|--------------------------------------------------------|----------|---------------|
| zero.middleware.auth.enabled | Enable auth middleware                                 | boolean  | false         |
| zero.middleware.auth.ignore  | The paths of prefix that will be ignored by middleware | []string | []            |
| zero.middleware.auth.basic   | Basic auth credentials as scheme of <user:pass>        | []string | []            |
| zero.middleware.auth.apiKey  | API key auth                                           | []string | []            |

#### Meta
Send application metadata as header to client.

| name                         | description                                            | type     | default value |
|------------------------------|--------------------------------------------------------|----------|---------------|
| zero.middleware.meta.enabled | Enable meta middleware                                 | boolean  | false         |
| zero.middleware.meta.ignore  | The paths of prefix that will be ignored by middleware | []string | []            |
| zero.middleware.meta.prefix  | Header key was formed as X-<Prefix>-XXX                | string   | RK            |

#### Tracing
| name                                                     | description                                            | type     | default value                    |
|----------------------------------------------------------|--------------------------------------------------------|----------|----------------------------------|
| zero.middleware.trace.enabled                            | Enable tracing middleware                              | boolean  | false                            |
| zero.middleware.trace.ignore                             | The paths of prefix that will be ignored by middleware | []string | []                               |
| zero.middleware.trace.exporter.file.enabled              | Enable file exporter                                   | boolean  | false                            |
| zero.middleware.trace.exporter.file.outputPath           | Export tracing info to files                           | string   | stdout                           |
| zero.middleware.trace.exporter.jaeger.agent.enabled      | Export tracing info to jaeger agent                    | boolean  | false                            |
| zero.middleware.trace.exporter.jaeger.agent.host         | As name described                                      | string   | localhost                        |
| zero.middleware.trace.exporter.jaeger.agent.port         | As name described                                      | int      | 6831                             |
| zero.middleware.trace.exporter.jaeger.collector.enabled  | Export tracing info to jaeger collector                | boolean  | false                            |
| zero.middleware.trace.exporter.jaeger.collector.endpoint | As name described                                      | string   | http://localhost:16368/api/trace |
| zero.middleware.trace.exporter.jaeger.collector.username | As name described                                      | string   | ""                               |
| zero.middleware.trace.exporter.jaeger.collector.password | As name described                                      | string   | ""                               |


#### RateLimit
| name                                      | description                                                          | type     | default value |
|-------------------------------------------|----------------------------------------------------------------------|----------|---------------|
| zero.middleware.rateLimit.enabled         | Enable rate limit middleware                                         | boolean  | false         |
| zero.middleware.rateLimit.ignore          | The paths of prefix that will be ignored by middleware               | []string | []            |
| zero.middleware.rateLimit.algorithm       | Provide algorithm, tokenBucket and leakyBucket are available options | string   | tokenBucket   |
| zero.middleware.rateLimit.reqPerSec       | Request per second globally                                          | int      | 0             |
| zero.middleware.rateLimit.paths.path      | Full path                                                            | string   | ""            |
| zero.middleware.rateLimit.paths.reqPerSec | Request per second by full path                                      | int      | 0             |

#### CORS
| name                                  | description                                                            | type     | default value        |
|---------------------------------------|------------------------------------------------------------------------|----------|----------------------|
| zero.middleware.cors.enabled          | Enable cors middleware                                                 | boolean  | false                |
| zero.middleware.cors.ignore           | The paths of prefix that will be ignored by middleware                 | []string | []                   |
| zero.middleware.cors.allowOrigins     | Provide allowed origins with wildcard enabled.                         | []string | *                    |
| zero.middleware.cors.allowMethods     | Provide allowed methods returns as response header of OPTIONS request. | []string | All http methods     |
| zero.middleware.cors.allowHeaders     | Provide allowed headers returns as response header of OPTIONS request. | []string | Headers from request |
| zero.middleware.cors.allowCredentials | Returns as response header of OPTIONS request.                         | bool     | false                |
| zero.middleware.cors.exposeHeaders    | Provide exposed headers returns as response header of OPTIONS request. | []string | ""                   |
| zero.middleware.cors.maxAge           | Provide max age returns as response header of OPTIONS request.         | int      | 0                    |

#### JWT
In order to make swagger UI and RK tv work under JWT without JWT token, we need to ignore prefixes of paths as bellow.

```yaml
jwt:
  ...
  ignore:
   - "/sw"
```

| name                                          | description                                                                      | type     | default value          |
|-----------------------------------------------|----------------------------------------------------------------------------------|----------|------------------------|
| zero.middleware.jwt.enabled                   | Optional, Enable JWT middleware                                                  | boolean  | false                  |
| zero.middleware.jwt.ignore                    | Optional, Provide ignoring path prefix.                                          | []string | []                     |
| zero.middleware.jwt.signerEntry               | Optional, Provide signerEntry name.                                              | string   | ""                     |
| zero.middleware.jwt.symmetric.algorithm       | Required if symmetric specified. One of HS256, HS384, HS512                      | string   | ""                     |
| zero.middleware.jwt.symmetric.token           | Optional, raw token for signing and verification                                 | string   | ""                     |
| zero.middleware.jwt.symmetric.tokenPath       | Optional, path of token file                                                     | string   | ""                     |
| zero.middleware.jwt.asymmetric.algorithm      | Required if symmetric specified. One of RS256, RS384, RS512, ES256, ES384, ES512 | string   | ""                     |
| zero.middleware.jwt.asymmetric.privateKey     | Optional, raw private key file for signing                                       | string   | ""                     |
| zero.middleware.jwt.asymmetric.privateKeyPath | Optional, private key file path for signing                                      | string   | ""                     |
| zero.middleware.jwt.asymmetric.publicKey      | Optional, raw public key file for verification                                   | string   | ""                     |
| zero.middleware.jwt.asymmetric.publicKeyPath  | Optional, public key file path for verification                                  | string   | ""                     |
| zero.middleware.jwt.tokenLookup               | Provide token lookup scheme, please see bellow description.                      | string   | "header:Authorization" |
| zero.middleware.jwt.authScheme                | Provide auth scheme.                                                             | string   | Bearer                 |

The supported scheme of **tokenLookup**

```
// Optional. Default value "header:Authorization".
// Possible values:
// - "header:<name>"
// - "query:<name>"
// Multiply sources example:
// - "header: Authorization,cookie: myowncookie"
```

#### Secure
| name                                         | description                                       | type     | default value   |
|----------------------------------------------|---------------------------------------------------|----------|-----------------|
| zero.middleware.secure.enabled               | Enable secure middleware                          | boolean  | false           |
| zero.middleware.secure.ignore                | Ignoring path prefix.                             | []string | []              |
| zero.middleware.secure.xssProtection         | X-XSS-Protection header value.                    | string   | "1; mode=block" |
| zero.middleware.secure.contentTypeNosniff    | X-Content-Type-Options header value.              | string   | nosniff         |
| zero.middleware.secure.xFrameOptions         | X-Frame-Options header value.                     | string   | SAMEORIGIN      |
| zero.middleware.secure.hstsMaxAge            | Strict-Transport-Security header value.           | int      | 0               |
| zero.middleware.secure.hstsExcludeSubdomains | Excluding subdomains of HSTS.                     | bool     | false           |
| zero.middleware.secure.hstsPreloadEnabled    | Enabling HSTS preload.                            | bool     | false           |
| zero.middleware.secure.contentSecurityPolicy | Content-Security-Policy header value.             | string   | ""              |
| zero.middleware.secure.cspReportOnly         | Content-Security-Policy-Report-Only header value. | bool     | false           |
| zero.middleware.secure.referrerPolicy        | Referrer-Policy header value.                     | string   | ""              |

#### CSRF
| name                                | description                                                                     | type     | default value         |
|-------------------------------------|---------------------------------------------------------------------------------|----------|-----------------------|
| zero.middleware.csrf.enabled        | Enable csrf middleware                                                          | boolean  | false                 |
| zero.middleware.csrf.ignore         | Ignoring path prefix.                                                           | []string | []                    |
| zero.middleware.csrf.tokenLength    | Provide the length of the generated token.                                      | int      | 32                    |
| zero.middleware.csrf.tokenLookup    | Provide csrf token lookup rules, please see code comments for details.          | string   | "header:X-CSRF-Token" |
| zero.middleware.csrf.cookieName     | Provide name of the CSRF cookie. This cookie will store CSRF token.             | string   | _csrf                 |
| zero.middleware.csrf.cookieDomain   | Domain of the CSRF cookie.                                                      | string   | ""                    |
| zero.middleware.csrf.cookiePath     | Path of the CSRF cookie.                                                        | string   | ""                    |
| zero.middleware.csrf.cookieMaxAge   | Provide max age (in seconds) of the CSRF cookie.                                | int      | 86400                 |
| zero.middleware.csrf.cookieHttpOnly | Indicates if CSRF cookie is HTTP only.                                          | bool     | false                 |
| zero.middleware.csrf.cookieSameSite | Indicates SameSite mode of the CSRF cookie. Options: lax, strict, none, default | string   | default               |


### Full YAML
```yaml
---
#app:
#  name: my-app                                            # Optional, default: "rk-app"
#  version: "v1.0.0"                                       # Optional, default: "v0.0.0"
#  description: "this is description"                      # Optional, default: ""
#  keywords: ["rk", "golang"]                              # Optional, default: []
#  homeUrl: "http://example.com"                           # Optional, default: ""
#  docsUrl: ["http://example.com"]                         # Optional, default: []
#  maintainers: ["rk-dev"]                                 # Optional, default: []
#logger:
#  - name: my-logger                                       # Required
#    description: "Description of entry"                   # Optional
#    domain: "*"                                           # Optional, default: "*"
#    default: false                                        # Optional, default: false, use as default logger entry
#    zap:                                                  # Optional
#      level: info                                         # Optional, default: info
#      development: true                                   # Optional, default: true
#      disableCaller: false                                # Optional, default: false
#      disableStacktrace: true                             # Optional, default: true
#      encoding: console                                   # Optional, default: console
#      outputPaths: ["stdout"]                             # Optional, default: [stdout]
#      errorOutputPaths: ["stderr"]                        # Optional, default: [stderr]
#      encoderConfig:                                      # Optional
#        timeKey: "ts"                                     # Optional, default: ts
#        levelKey: "level"                                 # Optional, default: level
#        nameKey: "logger"                                 # Optional, default: logger
#        callerKey: "caller"                               # Optional, default: caller
#        messageKey: "msg"                                 # Optional, default: msg
#        stacktraceKey: "stacktrace"                       # Optional, default: stacktrace
#        skipLineEnding: false                             # Optional, default: false
#        lineEnding: "\n"                                  # Optional, default: \n
#        consoleSeparator: "\t"                            # Optional, default: \t
#      sampling:                                           # Optional, default: nil
#        initial: 0                                        # Optional, default: 0
#        thereafter: 0                                     # Optional, default: 0
#      initialFields:                                      # Optional, default: empty map
#        key: value
#    lumberjack:                                           # Optional, default: nil
#      filename:
#      maxsize: 1024                                       # Optional, suggested: 1024 (MB)
#      maxage: 7                                           # Optional, suggested: 7 (day)
#      maxbackups: 3                                       # Optional, suggested: 3 (day)
#      localtime: true                                     # Optional, suggested: true
#      compress: true                                      # Optional, suggested: true
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
#event:
#  - name: my-event                                        # Required
#    description: "Description of entry"                   # Optional
#    domain: "*"                                           # Optional, default: "*"
#    default: false                                        # Optional, default: false, use as default event entry
#    encoding: console                                     # Optional, default: console
#    outputPaths: ["stdout"]                               # Optional, default: [stdout]
#    lumberjack:                                           # Optional, default: nil
#      filename:
#      maxsize: 1024                                       # Optional, suggested: 1024 (MB)
#      maxage: 7                                           # Optional, suggested: 7 (day)
#      maxbackups: 3                                       # Optional, suggested: 3 (day)
#      localtime: true                                     # Optional, suggested: true
#      compress: true                                      # Optional, suggested: true
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
#cert:
#  - name: my-cert                                         # Required
#    description: "Description of entry"                   # Optional, default: ""
#    domain: "*"                                           # Optional, default: "*"
#    caPath: "certs/ca.pem"                                # Optional, default: ""
#    certPemPath: "certs/server-cert.pem"                  # Optional, default: ""
#    keyPemPath: "certs/server-key.pem"                    # Optional, default: ""
#config:
#  - name: my-config                                       # Required
#    description: "Description of entry"                   # Optional, default: ""
#    domain: "*"                                           # Optional, default: "*"
#    path: "config/config.yaml"                            # Optional
#    envPrefix: ""                                         # Optional, default: ""
#    content:                                              # Optional, defualt: empty map
#      key: value
zero:
  - name: greeter                                          # Required
    port: 8080                                             # Required
    enabled: true                                          # Required
#    description: "greeter server"                         # Optional, default: ""
#    certEntry: my-cert                                    # Optional, default: "", reference of cert entry declared above
#    loggerEntry: my-logger                                # Optional, default: "", reference of cert entry declared above, STDOUT will be used if missing
#    eventEntry: my-event                                  # Optional, default: "", reference of cert entry declared above, STDOUT will be used if missing
#    sw:
#      enabled: true                                       # Optional, default: false
#      path: "sw"                                          # Optional, default: "sw"
#      jsonPath: [""]                                      # Optional
#      headers: ["sw:rk"]                                  # Optional, default: []
#    commonService:
#      enabled: true                                       # Optional, default: false
#      pathPrefix: ""                                      # Optional, default: "/rk/v1/"
#    docs:
#      enabled: true                                       # Optional, default: false
#      path: "docs"                                        # Optional, default: "docs"
#      specPath: ""                                        # Optional
#      headers: ["sw:rk"]                                  # Optional, default: []
#      style:                                              # Optional
#        theme: "light"                                    # Optional, default: "light"
#      debug: false                                        # Optional, default: false
#    static:
#      enabled: true                                       # Optional, default: false
#      path: "/static"                                     # Optional, default: /static
#      sourceType: local                                   # Optional, options: local, embed.FS can be used either, need to specify in code
#      sourcePath: "."                                     # Optional, full path of source directory
#    pprof:
#      enabled: true                                       # Optional, default: false
#      path: "/pprof"                                      # Optional, default: /pprof
#    prom:
#      enabled: true                                       # Optional, default: false
#      path: ""                                            # Optional, default: "metrics"
#      pusher:
#        enabled: false                                    # Optional, default: false
#        jobName: "greeter-pusher"                         # Required
#        remoteAddress: "localhost:9091"                   # Required
#        basicAuth: "user:pass"                            # Optional, default: ""
#        intervalMs: 10000                                 # Optional, default: 1000
#        certEntry: my-cert                                # Optional, default: "", reference of cert entry declared above
#    middleware:
#      ignore: [""]                                        # Optional, default: []
#      errorModel: google                                  # Optional, default: google, [amazon, google] are supported options
#      logging:
#        enabled: true                                     # Optional, default: false
#        ignore: [""]                                      # Optional, default: []
#        loggerEncoding: "console"                         # Optional, default: "console"
#        loggerOutputPaths: ["logs/app.log"]               # Optional, default: ["stdout"]
#        eventEncoding: "console"                          # Optional, default: "console"
#        eventOutputPaths: ["logs/event.log"]              # Optional, default: ["stdout"]
#      prom:
#        enabled: true                                     # Optional, default: false
#        ignore: [""]                                      # Optional, default: []
#      auth:
#        enabled: true                                     # Optional, default: false
#        ignore: [""]                                      # Optional, default: []
#        basic:
#          - "user:pass"                                   # Optional, default: []
#        apiKey:
#          - "keys"                                        # Optional, default: []
#      meta:
#        enabled: true                                     # Optional, default: false
#        ignore: [""]                                      # Optional, default: []
#        prefix: "rk"                                      # Optional, default: "rk"
#      trace:
#        enabled: true                                     # Optional, default: false
#        ignore: [""]                                      # Optional, default: []
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
#        ignore: [""]                                      # Optional, default: []
#        algorithm: "leakyBucket"                          # Optional, default: "tokenBucket"
#        reqPerSec: 100                                    # Optional, default: 1000000
#        paths:
#          - path: "/rk/v1/healthy"                        # Optional, default: ""
#            reqPerSec: 0                                  # Optional, default: 1000000
#      jwt:
#        enabled: true                                     # Optional, default: false
#        ignore: [ "" ]                                    # Optional, default: []
#        signerEntry: ""                                   # Optional, default: ""
#        skipVerify: false                                 # Optional, default: false
#        symmetric:                                        # Optional
#          algorithm: ""                                   # Required, default: ""
#          token: ""                                       # Optional, default: ""
#          tokenPath: ""                                   # Optional, default: ""
#        asymmetric:                                       # Optional
#          algorithm: ""                                   # Required, default: ""
#          privateKey: ""                                  # Optional, default: ""
#          privateKeyPath: ""                              # Optional, default: ""
#          publicKey: ""                                   # Optional, default: ""
#          publicKeyPath: ""                               # Optional, default: ""
#        tokenLookup: "header:<name>"                      # Optional, default: "header:Authorization"
#        authScheme: "Bearer"                              # Optional, default: "Bearer"
#      secure:
#        enabled: true                                     # Optional, default: false
#        ignore: [""]                                      # Optional, default: []
#        xssProtection: ""                                 # Optional, default: "1; mode=block"
#        contentTypeNosniff: ""                            # Optional, default: nosniff
#        xFrameOptions: ""                                 # Optional, default: SAMEORIGIN
#        hstsMaxAge: 0                                     # Optional, default: 0
#        hstsExcludeSubdomains: false                      # Optional, default: false
#        hstsPreloadEnabled: false                         # Optional, default: false
#        contentSecurityPolicy: ""                         # Optional, default: ""
#        cspReportOnly: false                              # Optional, default: false
#        referrerPolicy: ""                                # Optional, default: ""
#      csrf:
#        enabled: true                                     # Optional, default: false
#        ignore: [""]                                      # Optional, default: []
#        tokenLength: 32                                   # Optional, default: 32
#        tokenLookup: "header:X-CSRF-Token"                # Optional, default: "header:X-CSRF-Token"
#        cookieName: "_csrf"                               # Optional, default: _csrf
#        cookieDomain: ""                                  # Optional, default: ""
#        cookiePath: ""                                    # Optional, default: ""
#        cookieMaxAge: 86400                               # Optional, default: 86400
#        cookieHttpOnly: false                             # Optional, default: false
#        cookieSameSite: "default"                         # Optional, default: "default", options: lax, strict, none, default
#      cors:
#        enabled: true                                     # Optional, default: false
#        ignore: [""]                                      # Optional, default: []
#        allowOrigins:                                     # Optional, default: []
#          - "http://localhost:*"                          # Optional, default: *
#        allowCredentials: false                           # Optional, default: false
#        allowHeaders: []                                  # Optional, default: []
#        allowMethods: []                                  # Optional, default: []
#        exposeHeaders: []                                 # Optional, default: []
#        maxAge: 0                                         # Optional, default: 0
```

## Notice of V2
Master branch of this package is under upgrade which will be released to v2.x.x soon.

Major changes listed bellow. This will be updated with every commit.

| Last version | New version | Changes                                                                                                            |
|--------------|-------------|--------------------------------------------------------------------------------------------------------------------|
| v0.0.11      | v2          | TV is not supported because of LICENSE issue, new TV web UI will be released soon                                  |
| v0.0.11      | v2          | Remote repositry of ConfigEntry and CertEntry removed                                                              |
| v0.0.11      | v2          | Swagger json file and boot.yaml file could be embed into embed.FS and pass to rkentry                              |
| v0.0.11      | v2          | ZapLoggerEntry -> LoggerEntry                                                                                      |
| v0.0.11      | v2          | EventLoggerEntry -> EventEntry                                                                                     |
| v0.0.11      | v2          | LoggerEntry can be used as zap.Logger since all functions are inherited                                            |
| v0.0.11      | v2          | PromEntry can be used as prometheus.Registry since all functions are inherited                                     |
| v0.0.11      | v2          | rk-common dependency was removed                                                                                   |
| v0.0.11      | v2          | Entries are organized by EntryType instead of EntryName, so user can have same entry name with different EntryType |
| v0.0.11      | v2          | zero.middlewares -> gin.middleware in boot.yaml                                                                    |
| v0.0.11      | v2          | zero.middlewares.loggingZap -> zero.middleware.logging in boot.yaml                                                |
| v0.0.11      | v2          | zero.middlewares.metricsProm -> zero.middleware.prom in boot.yaml                                                  |
| v0.0.11      | v2          | zero.middlewares.tracingTelemetry -> zero.middleware.trace in boot.yaml                                            |
| v0.0.11      | v2          | All middlewares are now support zero.middleware.xxx.ignorePrefix options in boot.yaml                              |
| v0.0.11      | v2          | Middlewares support zero.middleware.ignorePrefix in boot.yaml as global scope                                      |
| v0.0.11      | v2          | LoggerEntry, EventEntry, ConfigEntry, CertEntry now support locale to distinguish in differerent environment       |
| v0.0.11      | v2          | LoggerEntry, EventEntry, CertEntry can be referenced to gin entry in boot.yaml                                     |
| v0.0.11      | v2          | Healthy API was replaced by Ready and Alive which also provides validation func from user                          |
| v0.0.11      | v2          | DocsEntry was added into rk-entry                                                                                  |
| v0.0.11      | v2          | rk-entry support utility functions of embed.FS                                                                     |
| v0.0.11      | v2          | rk-entry bumped up to v2                                                                                           |

## Development Status: Stable

## Build instruction
Simply run make all to validate your changes. Or run codes in example/ folder.

- make all

Run unit-test, golangci-lint, doctoc and gofmt.

## Test instruction
Run unit test with **make test** command.

Github workflow will automatically run unit test and golangci-lint for testing and lint validation.

## Contributing
We encourage and support an active, healthy community of contributors &mdash;
including you! Details are in the [contribution guide](CONTRIBUTING.md) and
the [code of conduct](CODE_OF_CONDUCT.md). The rk maintainers keep an eye on
issues and pull requests, but you can also report any negative conduct to
lark@rkdev.info.

Released under the [Apache 2.0 License](LICENSE).

