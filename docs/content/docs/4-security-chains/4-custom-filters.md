---
title: "Custom Filters"
weight: 4
---

# Custom Filters

While Rays Web Security provides robust out-of-the-box mechanisms like Form Login and Basic Authentication, you may occasionally need to implement proprietary authentication flows (e.g., verifying a specific API key header, an internal SSO token, or an OAuth JWT).

You can inject your own security logic directly into the request lifecycle using the `AddCustomFilter()` method on the builder. 

> **Important:** Custom filters are always evaluated **before** global filters (like BasicAuth or FormLogin).

```go
func (this *SecurityConfig) HttpSecurity() *HttpSecurity {
    return (&HttpSecurityBuilder{}).
        AddCustomFilter(&MyApiKeyFilter{}). // Will run before standard authentication
        AuthorizedHTTPRequests().
            AnyRequest().Authenticated().
        And().
        Basic().
        Build()
}
```

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

#### Example Filter Response

Here is what returning a default pipeline action looks like inside your `Authenticate` function:

```go
func (f *MyApiKeyFilter) Authenticate(handler SecurityHandler) SecurityFilterChainException {
    apiKey := handler.Header("X-API-KEY")
    
    if apiKey == "" {
        // Continue down the chain, perhaps BasicAuth can authenticate them
        return DefaultSecurityFilterChainException{}.Next()
    }
    
    if apiKey != "valid-key" {
        // Immediately reject the request with a 401
        return DefaultSecurityFilterChainException{}.ReportError(
            NewError("InvalidApiKey", "The provided key is invalid"), 401,
        )
    }
    
    // ... establish authentication in the context ...
    
    return DefaultSecurityFilterChainException{}.Next()
}
```

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
