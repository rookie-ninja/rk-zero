# Log interceptor
In this example, we will try to create go-zero server with log interceptor enabled.

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**  *generated with [DocToc](https://github.com/thlorenz/doctoc)*

- [Quick start](#quick-start)
  - [Code](#code)
- [Options](#options)
  - [Encoding](#encoding)
  - [OutputPath](#outputpath)
  - [Context Usage](#context-usage)
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
import     "github.com/rookie-ninja/rk-zero/interceptor/log/zap"
```

```go
	interceptors := []rest.Middleware{
        rkzerolog.Interceptor(),
    }
```

## Options
Log interceptor will init rkquery.Event, zap.Logger and entryName which will be injected into request context before user function.
As soon as user function returns, interceptor will write the event into files.

![arch](img/arch.png)

| Name | Default | Description |
| ---- | ---- | ---- |
| WithEntryNameAndType(entryName, entryType string) | entryName=gf, entryType=gf | entryName and entryType will be used to distinguish options if there are multiple interceptors in single process. |
| WithZapLoggerEntry(zapLoggerEntry *rkentry.ZapLoggerEntry) | [rkentry.GlobalAppCtx.GetZapLoggerEntryDefault()](https://github.com/rookie-ninja/rk-entry/blob/master/entry/context.go) | Zap logger would print to stdout with console encoding type. |
| WithEventLoggerEntry(eventLoggerEntry *rkentry.EventLoggerEntry) | [rkentry.GlobalAppCtx.GetEventLoggerEntryDefault()](https://github.com/rookie-ninja/rk-entry/blob/master/entry/context.go) | Event logger would print to stdout with console encoding type. |
| WithZapLoggerEncoding(ec int) | rkzerolog.ENCODING_CONSOLE | rkzerolog.ENCODING_CONSOLE and rkzerolog.ENCODING_JSON are available options. |
| WithZapLoggerOutputPaths(path ...string) | stdout | Both absolute path and relative path is acceptable. Current working directory would be used if path is relative. |
| WithEventLoggerEncoding(ec int) | rkzerolog.ENCODING_CONSOLE | rkzerolog.ENCODING_CONSOLE and rkzerolog.ENCODING_JSON are available options. |
| WithEventLoggerOutputPaths(path ...string) | stdout | Both absolute path and relative path is acceptable. Current working directory would be used if path is relative. |

```go
    // ********************************************
    // ********** Enable interceptors *************
    // ********************************************
	interceptors := []rest.Middleware{
		rkzerolog.Interceptor(
		// Entry name and entry type will be used for distinguishing interceptors. Recommended.
		// rkzerolog.WithEntryNameAndType("greeter", "zero"),
		//
		// Zap logger would be logged as JSON format.
		// rkzerolog.WithZapLoggerEncoding(rkzerolog.ENCODING_JSON),
		//
		// Event logger would be logged as JSON format.
		// rkzerolog.WithEventLoggerEncoding(rkzerolog.ENCODING_JSON),
		//
		// Zap logger would be logged to specified path.
		// rkzerolog.WithZapLoggerOutputPaths("logs/server-zap.log"),
		//
		// Event logger would be logged to specified path.
		// rkzerolog.WithEventLoggerOutputPaths("logs/server-event.log"),
		),
	}
```

### Encoding
- CONSOLE
No options needs to be provided. 
```shell script
2021-12-25T22:40:53.395+0800    INFO    log/greeter-server.go:99        Received request from client.   {"traceId": "e57df4e97df99db721cc21a29eda2fc6"}
```

```shell script
------------------------------------------------------------------------
endTime=2021-12-25T22:40:53.395707+08:00
startTime=2021-12-25T22:40:53.395514+08:00
elapsedNano=193428
timezone=CST
ids={"eventId":"d9f21bc1-0673-47b9-a766-abb5621c791d","traceId":"e57df4e97df99db721cc21a29eda2fc6"}
app={"appName":"rk","appVersion":"","entryName":"zero","entryType":"zero"}
env={"arch":"amd64","az":"*","domain":"*","hostname":"lark.local","localIP":"192.168.101.5","os":"darwin","realm":"*","region":"*"}
payloads={"apiMethod":"GET","apiPath":"/rk/v1/greeter","apiProtocol":"HTTP/1.1","apiQuery":"name=rk-dev","userAgent":"curl/7.64.1"}
error={}
counters={}
pairs={}
timing={}
remoteAddr=localhost:63437
operation=/rk/v1/greeter
resCode=200
eventStatus=Ended
EOE
```

- JSON
```go
    // ********************************************
    // ********** Enable interceptors *************
    // ********************************************
	interceptors := []rest.Middleware{
        rkzerolog.Interceptor(
            // Zap logger would be logged as JSON format.
            rkzerolog.WithZapLoggerEncoding(rkzerolog.ENCODING_JSON),
            //
            // Event logger would be logged as JSON format.
            rkzerolog.WithEventLoggerEncoding(rkzerolog.ENCODING_JSON),
        ),
    }
```
```json
{"level":"INFO","ts":"2021-12-25T22:42:03.922+0800","msg":"Received request from client.","traceId":"543264d4ac42db5d435de15425b6b88d"}
```
```json
{"endTime": "2021-12-25T22:42:03.922+0800", "startTime": "2021-12-25T22:42:03.922+0800", "elapsedNano": 163188, "timezone": "CST", "ids": {"eventId":"ecd87f4e-d965-4b0e-96d9-231acbdd2645","traceId":"543264d4ac42db5d435de15425b6b88d"}, "app": {"appName":"rk","appVersion":"","entryName":"zero","entryType":"zero"}, "env": {"arch":"amd64","az":"*","domain":"*","hostname":"lark.local","localIP":"192.168.101.5","os":"darwin","realm":"*","region":"*"}, "payloads": {"apiMethod":"GET","apiPath":"/rk/v1/greeter","apiProtocol":"HTTP/1.1","apiQuery":"name=rk-dev","userAgent":"curl/7.64.1"}, "error": {}, "counters": {}, "pairs": {}, "timing": {}, "remoteAddr": "localhost:51632", "operation": "/rk/v1/greeter", "eventStatus": "Ended", "resCode": "200"}
```

### OutputPath
- Stdout
No options needs to be provided. 

- Files
```go
    // ********************************************
    // ********** Enable interceptors *************
    // ********************************************
	interceptors := []rest.Middleware{
        rkzerolog.Interceptor(
            // Zap logger would be logged to specified path.
            rkzerolog.WithZapLoggerOutputPaths("logs/server-zap.log"),
            //
            // Event logger would be logged to specified path.
            rkzerolog.WithEventLoggerOutputPaths("logs/server-event.log"),
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
In this example, we enable log interceptor.

#### Start server
```shell script
$ go run greeter-server.go
```

#### Output
- Server side (zap & event)
```shell script
2021-12-25T22:42:56.551+0800	INFO	Received request from client.	{"traceId": "2c710ffa29bbdf361e483fc03ea36689"}
```

```shell script
------------------------------------------------------------------------
endTime=2021-12-25T22:42:56.551569+08:00
startTime=2021-12-25T22:42:56.551186+08:00
elapsedNano=382340
timezone=CST
ids={"eventId":"f3846888-d00f-4de7-ae1b-7852e64d786f","traceId":"2c710ffa29bbdf361e483fc03ea36689"}
app={"appName":"rk","appVersion":"","entryName":"zero","entryType":"zero"}
env={"arch":"amd64","az":"*","domain":"*","hostname":"lark.local","localIP":"192.168.101.5","os":"darwin","realm":"*","region":"*"}
payloads={"apiMethod":"GET","apiPath":"/rk/v1/greeter","apiProtocol":"HTTP/1.1","apiQuery":"name=rk-dev","userAgent":"curl/7.64.1"}
error={}
counters={}
pairs={}
timing={}
remoteAddr=localhost:55038
operation=/rk/v1/greeter
resCode=200
eventStatus=Ended
EOE
```

- Client side
```shell script
$ curl "localhost:8080/rk/v1/greeter?name=rk-dev"
{"Message":"Hello rk-dev!"}
```

### Code
- [greeter-server.go](greeter-server.go)
