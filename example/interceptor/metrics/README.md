# Metrics interceptor
In this example, we will try to create go-zero server with metrics interceptor enabled.

Metrics interceptor will collect bellow metrics with prometheus data format.
- RPC elapsed
- RPC error count
- RPC response code count

Users need to start a prometheus client locally export the data.
[rk-prom](https://github.com/rookie-ninja/rk-prom) would be a good option start prometheus client easily.

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**  *generated with [DocToc](https://github.com/thlorenz/doctoc)*

- [Quick start](#quick-start)
  - [Code](#code)
- [Options](#options)
  - [Override namespace and subsystem](#override-namespace-and-subsystem)
  - [Override Registerer](#override-registerer)
  - [Context Usage](#context-usage)
- [Example](#example)
  - [Start server](#start-server)
  - [Output](#output)
  - [Code](#code-1)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## Quick start
Get rk-zero package from the remote repository.

### Code
```go
import     "github.com/rookie-ninja/rk-zero/interceptor/metrics/prom"
```
```go
    // ********************************************
    // ********** Enable interceptors *************
    // ********************************************
	interceptors := []rest.Middleware{
        rkzerometrics.Interceptor(),
    }
```

## Options
In order to define prometheus style metrics, we need to define <namespace> and <subsystem>.
- namespace: rkentry.GlobalAppCtx().AppName ("rk" will be used by default.)
- subsystem: entryName (Provided as interceptor option. "zero" will be used by default.)

| Name | Description | Default Values |
| ---- | ---- | ---- |
| rkzerometrics.WithEntryNameAndType(entryName, entryType string) | Provide entry name and type if there are multiple extension interceptors needs to be used. | rk, zero |
| rkzerometrics.WithRegisterer(registerer prometheus.Registerer) | Provide prometheus registerer. | prometheus.DefaultRegisterer |

![arch](img/arch.png)

### Override namespace and subsystem
```go
func main() {
    // Override app name which would replace namespace value in prometheus.
    rkentry.GlobalAppCtx.GetAppInfoEntry().AppName = "newApp"

    // ********************************************
    // ********** Enable interceptors *************
    // ********************************************
	interceptors := []rest.Middleware{
        rkzerometrics.Interceptor(
            // Add metrics interceptor with entry name and entry type.
            // subsystem would be replaced with newEntry.
            rkzerometrics.Interceptor(rkzerometrics.WithEntryNameAndType("newEntry", "zero")),
        ),
    }

    // 1: Create go-zero server
    server := startGreeterServer(opts...)
    ...
}
```

### Override Registerer
```go
	interceptors := []rest.Middleware{
        rkzerometrics.Interceptor(
            // Provide new prometheus registerer.
            // Default value is prometheus.DefaultRegisterer
            rkzerometrics.WithRegisterer(prometheus.NewRegistry()),
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
### Start server
```shell script
$ go run greeter-server.go
```

### Output
- Server: localhost:1608/metrics

```shell script
$ curl localhost:1608/metrics
...
# HELP rk_greeter_elapsedNano Summary for name:elapsedNano and labels:[entryName entryType realm region az domain instance appVersion appName restMethod restPath type resCode]
# TYPE rk_greeter_elapsedNano summary
rk_greeter_elapsedNano{appName="rk",appVersion="",az="*",domain="*",entryName="greeter",entryType="zero",instance="lark.local",realm="*",region="*",resCode="200",restMethod="GET",restPath="/rk/v1/greeter",type="zero",quantile="0.5"} 150219
rk_greeter_elapsedNano{appName="rk",appVersion="",az="*",domain="*",entryName="greeter",entryType="zero",instance="lark.local",realm="*",region="*",resCode="200",restMethod="GET",restPath="/rk/v1/greeter",type="zero",quantile="0.9"} 150219
rk_greeter_elapsedNano{appName="rk",appVersion="",az="*",domain="*",entryName="greeter",entryType="zero",instance="lark.local",realm="*",region="*",resCode="200",restMethod="GET",restPath="/rk/v1/greeter",type="zero",quantile="0.99"} 150219
rk_greeter_elapsedNano{appName="rk",appVersion="",az="*",domain="*",entryName="greeter",entryType="zero",instance="lark.local",realm="*",region="*",resCode="200",restMethod="GET",restPath="/rk/v1/greeter",type="zero",quantile="0.999"} 150219
rk_greeter_elapsedNano_sum{appName="rk",appVersion="",az="*",domain="*",entryName="greeter",entryType="zero",instance="lark.local",realm="*",region="*",resCode="200",restMethod="GET",restPath="/rk/v1/greeter",type="zero"} 150219
rk_greeter_elapsedNano_count{appName="rk",appVersion="",az="*",domain="*",entryName="greeter",entryType="zero",instance="lark.local",realm="*",region="*",resCode="200",restMethod="GET",restPath="/rk/v1/greeter",type="zero"} 1
# HELP rk_greeter_resCode counter for name:resCode and labels:[entryName entryType realm region az domain instance appVersion appName restMethod restPath type resCode]
# TYPE rk_greeter_resCode counter
rk_greeter_resCode{appName="rk",appVersion="",az="*",domain="*",entryName="greeter",entryType="zero",instance="lark.local",realm="*",region="*",resCode="200",restMethod="GET",restPath="/rk/v1/greeter",type="zero"} 1
```

### Code
- [greeter-server.go](greeter-server.go)