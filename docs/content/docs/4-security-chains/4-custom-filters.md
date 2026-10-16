---
title: "Custom Filters"
weight: 4
---

# Custom Filters

While Rays Web Security provides robust out-of-the-box mechanisms like Form Login and Basic Authentication, you may occasionally need to implement proprietary authentication flows (e.g., verifying a specific API key header, an internal SSO token, or an OAuth JWT).

Custom filters are registered using the `AddCustomSecurityFilter(name string, obj any)` method on `HttpSecurityBuilder`, or fluently using `With()`.

> **Important:** Custom filters are always evaluated **before** global filters (like BasicAuth or FormLogin).

## How Custom Filters Work

Rather than requiring you to manually instantiate filter structs directly in your configuration methods, Rays Web Security allows custom filters to be defined as **Prototype Beams** managed by the Rays IoC container. This allows filters to easily inject dependencies (services, encoders, database clients, loggers) via `@:"Inject"` tags.

Filter registration involves two cooperating parts:

1. **Configuring the Security Chain (`With` and `AddCustomSecurityFilter`)**: In your `HttpSecurity` configuration, you register a filter identifier (name) and an arbitrary configuration struct pointer using `AddCustomSecurityFilter(name, obj)`—either directly or fluently via the `With()` method on `HttpSecurityBuilder`. This populates an internal `map[string]any` in `HttpSecurity`, retrievable via `httpSecurity.SecurityFilters()`.
2. **Contextual Filter Activation (`WithContext`)**: Your custom filter struct implements the Rays `BeamPostConstructWithContext` interface (`WithContext(ctx context.Context) Error`) and is scoped as a `Prototype`. When Rays prepares to inject candidate filters into `HttpSecurity`, it invokes `WithContext()`. The filter retrieves the parent `*HttpSecurity` from the context, checks `httpSecurity.SecurityFilters()` for its name and type, and decides whether it is needed for that chain.

If `WithContext()` returns `nil`, Rays injects the filter into the chain. If it returns an `Error`, the filter is excluded from that specific `HttpSecurity`.

### 1. Registration in `HttpSecurityBuilder`

Using Go 1.27 generic method support, `HttpSecurityBuilder.With()` accepts a function taking `*HttpSecurityBuilder` and returning an object implementing `HttpSecurityBuilderOption` (requiring an `And() *HttpSecurityBuilder` method).

The configuration struct (e.g., `MyApiKeyFilterConfig`) maintains a private reference to `*HttpSecurityBuilder`, exposes chainable methods to configure itself, and implements `And() *HttpSecurityBuilder`. A constructor function such as `MyApiKey(*HttpSecurityBuilder) *MyApiKeyFilterConfig` registers the configuration struct via `AddCustomSecurityFilter` and returns it for chaining:

```go
package configurations

import (
    . "github.com/BeamFoundry/rays-web-security/pkg/config"
    . "github.com/BeamFoundry/rays/pkg/core"
)

type MyApiKeyFilterConfig struct {
    httpSecurityBuilder *HttpSecurityBuilder
    headerName          string
    validKey            string
}

func (this *MyApiKeyFilterConfig) HeaderName(headerName string) *MyApiKeyFilterConfig {
    this.headerName = headerName
    return this
}

func (this *MyApiKeyFilterConfig) ValidKey(validKey string) *MyApiKeyFilterConfig {
    this.validKey = validKey
    return this
}

func (this *MyApiKeyFilterConfig) And() *HttpSecurityBuilder {
    this.httpSecurityBuilder.AddCustomSecurityFilter("myApiKeyFilter", config)
    return this.httpSecurityBuilder
}

func MyApiKey(builder *HttpSecurityBuilder) *MyApiKeyFilterConfig {
    config := &MyApiKeyFilterConfig{
        httpSecurityBuilder: builder,
    }
    return config
}

type SecurityConfig struct {
    Configuration
}

func (this *SecurityConfig) HttpSecurity() *HttpSecurity {
    return (&HttpSecurityBuilder{}).
        With(MyApiKey).
            HeaderName("X-API-KEY").
            ValidKey("secret-token").
        And().
        AuthorizedHTTPRequests().
            AnyRequest().Authenticated().
        And().
        Basic().
        Build()
}
```

### 2. Implementing the Custom Filter Beam

To implement a custom filter that integrates with this injection mechanism:
1. Embed `Component` and `Prototype` to mark it as a prototype Beam.
2. Implement `SecurityFilter` (`Authenticate` and `AuthenticationRequired`).
3. Implement `BeamPostConstructWithContext` (`WithContext(ctx context.Context) Error`).

```go
package filters

import (
    "context"

    . "github.com/BeamFoundry/rays-web-security/pkg/config"
    . "github.com/BeamFoundry/rays-web-security/pkg/core"
    . "github.com/BeamFoundry/rays/pkg/core"
    . "github.com/BeamFoundry/rays/pkg/lang"
)

type MyApiKeyFilter struct {
    Component
    Prototype

    logger Logging               `@:"Inject"`
    config *MyApiKeyFilterConfig
}

var _, _ = any(&MyApiKeyFilter{}).(Stereotype)
var _ SecurityFilter = &MyApiKeyFilter{}
var _ BeamPostConstructWithContext = &MyApiKeyFilter{}

func (this *MyApiKeyFilter) WithContext(ctx context.Context) Error {
    if ct := ctx.Value(PrototypeContextParentInstance); ct != nil {
        httpSecurity, ok := ct.(*HttpSecurity)
        if !ok {
            return NewError("IllegalArgumentException", "Only HttpSecurity may inject this filter")
        }

        // Check if this HttpSecurity configured this filter
        raw, ok := httpSecurity.SecurityFilters()["myApiKeyFilter"]
        if !ok {
            return NewError("IllegalArgumentException", "HttpSecurity does not configure myApiKeyFilter")
        }

        // Validate configuration struct pointer type
        cfg, ok := raw.(*MyApiKeyFilterConfig)
        if !ok {
            return NewError("IllegalArgumentException", "Invalid configuration type for myApiKeyFilter")
        }

        this.config = cfg
    }
    return nil
}

func (this *MyApiKeyFilter) Authenticate(handler SecurityHandler) SecurityFilterChainException {
    apiKey := handler.Header(this.config.headerName)

    if apiKey == "" {
        // Continue down the chain, allowing other filters (e.g. BasicAuth) to evaluate
        return DefaultSecurityFilterChainException{}.Next()
    }

    if apiKey != this.config.validKey {
        return DefaultSecurityFilterChainException{}.ReportError(
            NewError("InvalidApiKey", "The provided API key is invalid"), 401,
        )
    }

    // ... establish authentication in SecurityContext ...

    return DefaultSecurityFilterChainException{}.Next()
}

func (this *MyApiKeyFilter) AuthenticationRequired(handler SecurityHandler) SecurityFilterChainException {
    return DefaultSecurityFilterChainException{}.ReportError(
        NewError("HttpException", "Authentication Required"), 401,
    )
}
```

> **Note on `AddCustomFilter()`:** The earlier `AddCustomFilter(filter SecurityFilter)` method on `HttpSecurityBuilder` is now **deprecated**. It required manually instantiating filter structs within configuration methods, preventing them from taking advantage of Rays dependency injection. `AddCustomSecurityFilter` solves this by decoupling configuration parameters from filter instantiation.

## The Interfaces

To build a custom filter, you need to implement the `SecurityFilter` interface from `pkg/core`. You will interact heavily with the `SecurityHandler` and `SecurityFilterChainException` interfaces.

### 1. The `SecurityFilter` Interface

Your custom filter must implement two primary methods:

*   **`Authenticate`**: Evaluates the request. If it can establish an authenticated user (or intentionally blocks the request), it dictates what happens next.
*   **`AuthenticationRequired`**: Defines what the chain should do if no previous filter succeeded and the user tries to access a restricted path.

```go
type SecurityFilter interface {
    Authenticate(handler SecurityHandler) SecurityFilterChainException
    AuthenticationRequired(handler SecurityHandler) SecurityFilterChainException
}
```

### 2. The `SecurityHandler`

Rays Web Security is designed to be **web-framework agnostic**. The `SecurityHandler` acts as an abstraction layer over the underlying web framework (like Rays Fiber). It provides a standardized API to interact with the HTTP request, response, and session without coupling your security logic directly to a specific router.

```go
type SecurityHandler interface {
    Cookie(name string) (*http.Cookie, error)
    SetCookie(cookie *http.Cookie)
    FormValue(name string) string
    Header(name string) string
    SetHeader(name, value string)
    Method() string
    Path() string

    SessionReset()
    SessionRefresh()
    SessionValue(key string) any
    SetSessionValue(key string, obj any)

    URL() *url.URL
    BindBody(obj any) error
    Redirect(to string, code int) error
    RenderView(view string, data map[string]any) error
    Error(code int, message string) error
    Write(p []byte) (n int, err error)

    Next() error // Enable the next handler
}
```

### 3. Pipeline Control (`SecurityFilterChainException`)

Instead of passing Go `error` types directly, filters dictate the flow of the security chain by returning a `SecurityFilterChainException`.

#### Default Action Factory

Implementing this interface manually would be tedious. Rays Web Security provides `DefaultSecurityFilterChainException` equipped with several fluent factory methods that automatically map to framework actions (`NEXT`, `ERROR`, `REDIRECT`, `RENDER`):

*   **`Next()`**: Instructs the framework to proceed with the next middleware in the chain.
*   **`ReportError(err Error, code int)`**: Aborts the chain and reports an HTTP error using the configured code.
*   **`RedirectTo(url string)`**: Aborts the chain and redirects the user (defaults to HTTP 302).
*   **`RedirectToWithCode(url string, code int)`**: Aborts the chain and redirects using a specific HTTP code.
*   **`RenderView(view string, data map[string]any)`**: Aborts the chain and renders a specific template view.

### 4. Registering Endpoints (`SecurityEndpointRegistration`)

Some filters need to expose their own HTTP endpoints (for example, rendering a custom login page or handling an OAuth callback). If your custom filter implements the `SecurityEndpointRegistration` interface, the framework will automatically call it during initialization, allowing you to register technical routes on the internal `SecurityRouter`.

```go
type SecurityEndpointRegistration interface {
    RegisterSecurityEndpoint(router SecurityRouter)
}

type SecurityRouter interface {
    Group(path string) SecurityRouter
    Use(handler func(SecurityHandler) error)
    Get(path string, handler func(SecurityHandler) error)
    Post(path string, handler func(SecurityHandler) error)
}
```

**Example Implementation:**
```go
// Using a pointer receiver is highly recommended for stateful components
func (f *MyApiKeyFilter) RegisterSecurityEndpoint(router SecurityRouter) {
    router.Get("/auth/my-api-key/info", func(ctx SecurityHandler) error {
        _, err := ctx.Write([]byte("API Key Auth is enabled"))
        return err
    })
}
```

### 5. Session Awareness (`SessionAwareFilter`)

By default, if your `SessionCreationPolicy` is set to `.IfRequired()`, the framework dynamically assesses whether to provision HTTP sessions.

If your custom filter relies on session storage to function properly, you **must** implement the `SessionAwareFilter` marker interface. This explicitly signals to the framework that session management should be enabled for this chain.

In Go, the cleanest way to implement a marker interface is to embed it anonymously in your struct:

```go
type MyApiKeyFilter struct {
    Component // Rays framework component marker
    SessionAwareFilter // Anonymous embedding satisfies the marker interface

    // ... other fields ...
}
```
