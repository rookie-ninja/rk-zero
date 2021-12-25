# Trace interceptor
In this example, we will try to create go-zero server with trace interceptor enabled.

Trace interceptor has bellow options currently while exporting tracing information.

| Exporter | Description |
| ---- | ---- |
| Stdout | Export as JSON style. |
| Local file | Export as JSON style. |
| Jaeger | Export to jaeger collector or agent. |

**Please make sure panic interceptor to be added at last in chain of interceptors.**

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**  *generated with [DocToc](https://github.com/thlorenz/doctoc)*

- [Quick start](#quick-start)
- [Options](#options)
  - [Exporter](#exporter)
    - [Stdout exporter](#stdout-exporter)
    - [File exporter](#file-exporter)
    - [Jaeger exporter](#jaeger-exporter)
- [Example](#example)
  - [Start server and client](#start-server-and-client)
  - [Output](#output)
    - [Stdout exporter](#stdout-exporter-1)
    - [Jaeger exporter](#jaeger-exporter-1)
  - [Code](#code)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## Quick start
Get rk-zero package from the remote repository.

```go
go get -u github.com/rookie-ninja/rk-zero
```
```go
    // ********************************************
    // ********** Enable interceptors *************
    // ********************************************
	interceptors := []rest.Middleware{
		rkzerotrace.Interceptor(
		// Entry name and entry type will be used for distinguishing interceptors. Recommended.
		//rkzerotrace.WithEntryNameAndType("greeter", "zero"),
		//
		// Provide an exporter.
		//rkzerotrace.WithExporter(exporter),
		//
		// Provide propagation.TextMapPropagator
		// rkzerotrace.WithPropagator(<propagator>),
		//
		// Provide SpanProcessor
		// rkzerotrace.WithSpanProcessor(<span processor>),
		//
		// Provide TracerProvider
		// rkzerotrace.WithTracerProvider(<trace provider>),
		),
	}
```

## Options
If client didn't enable trace interceptor, then server will create a new trace span by itself. If client sends a tracemeta to server, 
then server will use the same traceId.

| Name | Description | Default |
| ---- | ---- | ---- |
| WithEntryNameAndType(entryName, entryType string) | Provide entryName and entryType, recommended. | entryName=zero, entryType=zero |
| WithExporter(exporter sdktrace.SpanExporter) | User defined exporter. | [Stdout exporter](https://pkg.go.dev/go.opentelemetry.io/otel/exporters/stdout) with pretty print and disabled metrics |
| WithSpanProcessor(processor sdktrace.SpanProcessor) | User defined span processor. | [NewBatchSpanProcessor](https://pkg.go.dev/go.opentelemetry.io/otel/sdk/trace#NewBatchSpanProcessor) |
| WithPropagator(propagator propagation.TextMapPropagator) | User defined propagator. | [NewCompositeTextMapPropagator](https://pkg.go.dev/go.opentelemetry.io/otel/propagation#TextMapPropagator) |

![arch](img/arch.png)

### Exporter
#### Stdout exporter
```go
    // ****************************************
    // ********** Create Exporter *************
    // ****************************************

    // Export trace to stdout with utility function
    //
    // Bellow function would be while creation
    // set.Exporter, _ = stdout.NewExporter(
    //     stdout.WithPrettyPrint(),
    //     stdout.WithoutMetricExport())
    exporter := rkzerotrace.CreateFileExporter("stdout")

    // Users can define own stdout exporter by themselves.
	exporter, _ := stdouttrace.New(stdouttrace.WithPrettyPrint())
```

#### File exporter
```go
    // ****************************************
    // ********** Create Exporter *************
    // ****************************************

    // Export trace to local file system
    exporter := rkzerotrace.CreateFileExporter("logs/trace.log")
```

#### Jaeger exporter
```go
    // ****************************************
    // ********** Create Exporter *************
    // ****************************************

	// Export trace to jaeger agent
	exporter := rkzerotrace.CreateJaegerExporter(jaeger.WithAgentEndpoint())
```

## Example
### Start server and client
```shell script
$ go run greeter-server.go
```

### Output
#### Stdout exporter
If logger interceptor enabled, then traceId would be attached to event and zap logger.

go-zero web framework embedded tracing for each RPC call which cannot be turned off.

As a result, there will be two spans initially.

- Server side trace log
```shell script
[
    {
        "SpanContext": {
                "TraceID": "917cd14abb2a33c0a168596bbba657ae",
                "SpanID": "1d34bf94725ec5cb",
                "TraceFlags": "01",
                "TraceState": "",
                "Remote": false
        },
        "Parent": {
                "TraceID": "917cd14abb2a33c0a168596bbba657ae",
                "SpanID": "86212c793460c7f4",
                "TraceFlags": "00",
                "TraceState": "",
                "Remote": true
        },

        ...
```

- Server side log (zap & event)
```shell script
2021-11-01T18:37:00.661+0800    INFO    tracing/greeter-server.go:88    Received request from client.   {"traceId": "21b908d912649d4383705e57c4145d58"}
```

```shell script
------------------------------------------------------------------------
endTime=2021-12-26T03:00:28.503626+08:00
startTime=2021-12-26T03:00:28.503413+08:00
elapsedNano=212776
timezone=CST
ids={"eventId":"7725b8d6-1812-456b-bcd9-8e512c8898b0","traceId":"917cd14abb2a33c0a168596bbba657ae"}
app={"appName":"rk","appVersion":"","entryName":"zero","entryType":"zero"}
env={"arch":"amd64","az":"*","domain":"*","hostname":"lark.local","localIP":"192.168.101.5","os":"darwin","realm":"*","region":"*"}
payloads={"apiMethod":"GET","apiPath":"/rk/v1/greeter","apiProtocol":"HTTP/1.1","apiQuery":"name=rk-dev","userAgent":"curl/7.64.1"}
error={}
counters={}
pairs={}
timing={}
remoteAddr=localhost:54289
operation=/rk/v1/greeter
resCode=200
eventStatus=Ended
EOE
```

- Client side
```shell script
$ curl -vs "localhost:8080/rk/v1/greeter?name=rk-dev"
...
< X-Trace-Id: 917cd14abb2a33c0a168596bbba657ae
```

#### Jaeger exporter
![Jaeger](img/jaeger.png)

### Code
- [greeter-server.go](greeter-server.go)
