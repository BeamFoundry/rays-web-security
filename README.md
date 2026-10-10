# BeamFoundry Rays Web Security 🛡️

**Rays Web Security** brings the declarative power and robust architecture of Spring Security directly to Go.

Built natively on top of the Rays IoC container, this package provides authentication, authorization, and
protection against common exploits. It integrates seamlessly with web frameworks (like Rays Fiber) to secure
your HTTP endpoints using clean, fluent builder chains.

## Introduction & Architecture

Securing enterprise applications often leads to messy, scattered middleware across various routers.
Rays Web Security centralizes this logic into declarative **Security Filter Chains**.

### Core Architectural Features

1. **Declarative Authorization:** Define endpoint security rules using a highly expressive `HttpSecurityBuilder`
  rather than imperative `if/else` blocks inside your handlers.
2. **Pluggable Authentication:** Easily swap out how users are authenticated by implementing the
  `AuthenticationProvider` or `UserDetailsService` interfaces.
3. **ThreadLocal Context:** Web Security utilizes `github.com/timandy/routine` to store the currently
  authenticated user in a ThreadLocal `SecurityContext`. Your deeper service layers can retrieve the
  user without needing the HTTP request object passed down.
4. **IoC Native Auto-Configuration:** The framework provides default security implementations out of
  the box, which you can easily override by defining your own Beams.

### 📦 Package Structure & Imports

To prevent circular dependencies and maintain clean boundaries, Rays Web Security is split into distinct packages:

*   `github.com/BeamFoundry/rays-web-security`: The root package. You underscore-import this in `main.go` to
  trigger the internal auto-configurations.
*   `.../pkg/core`: Contains **all interfaces** (`UserDetails`, `PasswordEncoder`, `SecurityContextHolder`, etc.).
*   `.../pkg/config`: Contains the `HttpSecurityBuilder` types.
*   `.../pkg/auth`: Contains concrete `AuthenticationProvider` implementations.
*   `.../pkg/password`: Contains concrete `PasswordEncoder` implementations.
*   `.../pkg/rememberme`: Contains `RememberMeService` implementations.
*   `.../pkg/testing`: Contains in-memory mock implementations for Ginkgo test suites.

### 🧹 Simplifying with Dot Imports
To keep your domain code clean, it is highly recommended to use Go's dot import feature for the core and config packages:

```go
import (
    . "github.com/BeamFoundry/rays-web-security/pkg/core"
    . "github.com/BeamFoundry/rays-web-security/pkg/config"
)
```

## Quickstart & Setup

To secure your application, you need to construct an `HttpSecurity` Beam. This tells the framework which endpoints require authentication and which are public.

### 📦 Installation

```bash
go get github.com/BeamFoundry/rays-web-security
```

### The Minimal Security Configuration

Here is a basic configuration that uses **Basic Authentication** and secures all endpoints except for the public login and health-check routes.

*Note: The framework automatically provisions a default `PasswordEncoder`, so you don't even need to define one to get started!*

```go
package configurations

import (
    . "github.com/BeamFoundry/rays-web-security/pkg/config"
    . "github.com/BeamFoundry/rays/pkg/core"
)

type SecurityConfig struct {
    Configuration
}

// Construct the HttpSecurity rules using the Builder
func (this *SecurityConfig) HttpSecurity() *HttpSecurity {
    return (&HttpSecurityBuilder{}).
        AuthorizedHTTPRequests().
        Paths("/api/public/**", "/health").PermitAll().
        Paths("/api/admin/**").HasAuthority("ROLE_ADMIN").
        And().
        AnyRequest().Authenticated().
        Basic(). // Enables Basic Authentication by default
        Build()
}

```

### The Entrypoint

In your `main.go`, you must underscore-import the root `rays-web-security` package. This triggers the `internal/autoconfig` module, which registers the default password encoders, context holders, and authentication managers into the Rays IoC container.

```go
package main

import (
    "os"
    "github.com/BeamFoundry/rays"

    // Essential: Registers core security auto-configurations
    _ "github.com/BeamFoundry/rays-web-security"
)

func main() {
    ctx := rays.ApplicationContext()
    ctx.EnableScanning()

    if err := ctx.Initialize(); err != nil {
        err.LogErrorWithStackTrace()
        os.Exit(1)
    }

    ctx.Run()
}
```

## Authentication & Remember Me

To authenticate users, Rays Web Security needs to know how to look them up and how to verify their passwords.


### The `UserDetails` Interface

First, adapt your domain model to fulfill the framework's `UserDetails` interface, located in `pkg/core`.

Note that the framework provides a convenient `Authority` string alias to easily generate `GrantedAuthority` slice elements.

```go
package models

import . "github.com/BeamFoundry/rays-web-security/pkg/core"

type User struct {
    ID           uint
    Email        string
    PasswordHash string
    Role         string
}

// Implement the UserDetails interface
func (u *User) GetUsername() string { return u.Email }
func (u *User) GetPassword() string { return u.PasswordHash }
func (u *User) GetAuthorities() []GrantedAuthority {
    return []GrantedAuthority{ Authority("ROLE_" + u.Role) }
}

// These return false when the account is active and unrestricted
func (u *User) IsExpired() bool           { return false }
func (u *User) IsCredentialExpired() bool { return false }
func (u *User) IsDisabled() bool          { return false }
func (u *User) IsLocked() bool            { return false }
```


### Implementing `UserDetailsService`

Next, create a Service that implements `UserDetailsService`. The framework will automatically detect this Beam and use it during the login process.

If the user cannot be found, you simply return `nil`, and the framework will handle the failed authentication safely.

```go
package security

import (
    . "github.com/BeamFoundry/rays-web-security/pkg/core"
    . "github.com/BeamFoundry/rays/pkg/core"
    . "github.com/BeamFoundry/rays/pkg/lang"
)

type DomainUserDetailsService struct {
    Service
    userRepo *UserRepository `@:"Inject"`
}

func (s *DomainUserDetailsService) LoadUserByUsername(username string) UserDetails {
    userOpt := s.userRepo.FindByEmail(username)

    // Return the user if found
    if user, ok := userOpt.Get(); ok {
        return user
    }

    // Return nil if the user does not exist
    return nil
}

```

### Password Encoding

Never store plain-text passwords. When you boot the application, `internal/autoconfig` automatically registers a highly secure, upgradeable default `PasswordEncoder`.

#### The Delegating Password Encoder

To support seamless algorithm migrations over time (a best practice from Spring Security), the default encoder is a `DelegatingPasswordEncoder`.

It automatically wraps a `BCryptPasswordEncoder` (with a cost of 10) mapped to the "bcrypt" prefix. This means your hashed passwords will automatically be formatted with a prefix, looking something like this:
`{bcrypt}$2a$10$wN1FzZ2...`

#### Overriding the Default Encoder

If you need to override this default (for example, to increase the hashing cost to 12 or to add support for legacy passwords), you can simply define your own `PasswordEncoder` Beam:

```go
package security

import (
    . "github.com/BeamFoundry/rays-web-security/pkg/core"
    . "github.com/BeamFoundry/rays-web-security/pkg/password"
    . "github.com/BeamFoundry/rays/pkg/core"
)

type PasswordConfig struct {
    Configuration
}

// Overrides the auto-configured DelegatingPasswordEncoder
func (this *PasswordConfig) PasswordEncoder() PasswordEncoder {
    return DelegatingPasswordEncoder{}.New(
        "bcrypt",
        map[string]PasswordEncoder{
            "bcrypt": BCryptPasswordEncoder{}.New(12), // Increased cost!
            "noop":   NoOpPasswordEncoder{}.New(),     // Support legacy plaintext (Not Recommended!)
        },
    )
}

```

### Remember Me Services

To keep users logged in across browser sessions without relying solely on long-lived session cookies, you can leverage the `RememberMeService` interface.

The framework provides a `TokenBasedRememberMeService` in `pkg/rememberme`. For a robust enterprise configuration, you should avoid hardcoding secrets and instead use Rays' `ConfigurationProperties` to load your configuration from YAML.

#### Configuration Options & Defaults

The `TokenBasedRememberMeService` provides several fluent builder methods to customize its behavior:

| Method | Default Value | Description |
| :--- | :--- | :--- |
| `WithParameter()` | "remember-me" | The HTML form input checked to determine if the cookie should be set. |
| `WithCookieName()` | "remember-me" | The name of the cookie sent to the browser. |
| `WithCookieDomain()` | "" | The domain restriction for the cookie. |
| `WithCookieSecure()` | false | Whether the secure (HTTPS-only) bit should be set on the cookie. |
| `WithValidity()` | 1209600 (14 days) | How long, in seconds, the cookie will be valid. |

#### Example: Externalized Configuration

First, define your YAML configuration. We explicitly provide the default values here for reference:

```yaml
### application.yaml
app:
  security:
    remember-me:
      key: "super-secret-production-key" # REQUIRED - The secret key used for hashing
      parameter: "remember-me"           # Default: "remember-me"
      cookie-name: "remember-me"         # Default: "remember-me"
      cookie-domain: ""                  # Default: ""
      cookie-secure: false               # Default: false
      validity: 1209600                  # Default: 1209600 (14 days in seconds)
```

Next, create the `ConfigurationProperties` struct. **Notice that the mapped fields are private (unexported)**, enforcing strict encapsulation:

```go
package configurations

import (
    . "github.com/BeamFoundry/rays-web-security/pkg/core"
    . "github.com/BeamFoundry/rays-web-security/pkg/rememberme"
    . "github.com/BeamFoundry/rays/pkg/core"
)

// 1. Bind the YAML properties to private fields
type RememberMeProperties struct {
    ConfigurationProperties `Name:"app.security.remember-me"`
    key          string
    parameter    string
    cookieName   string
    cookieDomain string
    cookieSecure bool
    validity     int
}

// 2. The Security Configuration
type RememberMeConfig struct {
    Configuration
}

// 3. Inject the properties AND the UserDetailsService dynamically
func (this *RememberMeConfig) RememberMe(
    that struct {
        props   *RememberMeProperties `@:"Inject"`
        userSvc UserDetailsService    `@:"Inject"`
    },
) RememberMeService {

    // Construct and configure the service using the securely encapsulated properties
    return TokenBasedRememberMeService{}.
        New(that.props.key, that.userSvc).
        WithParameter(that.props.parameter).
        WithCookieName(that.props.cookieName).
        WithCookieDomain(that.props.cookieDomain).
        WithCookieSecure(that.props.cookieSecure).
        WithValidity(that.props.validity)
}

```

Once registered, you can inject it directly into your `HttpSecurityBuilder` by calling `.RememberMe(that.rememberme)`.


## Security Chains & Authorization

Now that you have configured how users authenticate, you must define the `HttpSecurity` rules to intercept incoming HTTP requests and determine if they should be allowed to proceed.

### The `HttpSecurityBuilder`

You configure authorization rules using a fluent builder pattern. The framework evaluates your `Paths()` rules **in the order they are defined**. Use the `.And()` method to return to the parent builder context and configure other security features.

Here is a typical default setup for an API using Basic Authentication:

```go
package configurations

import (
    . "github.com/BeamFoundry/rays-web-security/pkg/config"
    . "github.com/BeamFoundry/rays/pkg/core"
)

type RouteSecurityConfig struct {
    Configuration
}

func (this *RouteSecurityConfig) HttpSecurity() *HttpSecurity {
    return (&HttpSecurityBuilder{}).
        AuthorizedHTTPRequests().
            // Evaluate specific rules first
            Paths("/api/public/**").PermitAll().
            Paths("/api/admin/**").HasRole("ADMIN").

            // Fallback for everything else
            AnyRequest().Authenticated().
        And().
        Basic().
        Build()
}

```

#### AntPath Style Matching

When securing endpoints using `Paths(...)` (or using `Match()` for multiple chains), Rays Web Security uses **AntPath style matching**. This provides highly expressive wildcard routing:

*   `?` matches exactly one character.
*   `*` matches zero or more characters within a *single* path segment.
*   `**` matches zero or more *path segments*.

**Examples:**
*   `/api/products/*` matches `/api/products/123` but **not** `/api/products/123/reviews`.
*   `/api/admin/**` matches `/api/admin`, `/api/admin/users`, and `/api/admin/users/delete`.

### Authorization Policies

When chaining rules after `Paths(...)` or `AnyRequest()`, you are interacting with the `HttpPolicy` builder. Rays Web Security provides several built-in policies to secure your endpoints:

| Policy Method | Description |
| :--- | :--- |
| `PermitAll()` | Permits access to everyone (including unauthenticated anonymous users). |
| `DenyAll()` | Denies access to everyone (useful as a strict fallback at the end of the chain). |
| `Anonymous()` | Permits access **only** to unauthenticated (anonymous) users. |
| `Authenticated()` | Permits access **only** to users who are logged in. |
| `HasAuthority(string)` | Requires the user to have the *exact* authority string provided (e.g., "ROLE_ADMIN"). |
| `HasAnyAuthority([]string)` | Requires the user to have at least one of the exact authorities provided. |
| `HasRole(string)` | Requires the specified role. **Note:** The framework automatically prefixes this string with "ROLE_". |
| `HasAnyRole([]string)` | Requires the user to have at least one of the specified roles (automatically prefixed). |

> **Role vs. Authority:** `HasRole("ADMIN")` is functionally identical to `HasAuthority("ROLE_ADMIN")`. The Role variant simply saves you from typing the prefix!

### Multiple Security Chains

In complex applications, you might need entirely different security configurations for different parts of your app. For example, a stateless API using Basic Authentication for `/api/**`, and a stateful HTML application using Form Login for `/web/**`.

You can achieve this by defining **multiple `*HttpSecurity` Beams**. To instruct the framework on which requests a specific chain should intercept, use the `Match(path string, paths ...string)` method at the very beginning of your builder chain.

```go
package configurations

import (
    . "github.com/BeamFoundry/rays-web-security/pkg/config"
    . "github.com/BeamFoundry/rays/pkg/core"
)

type MultiChainSecurityConfig struct {
    Configuration
}

// Chain 1: Protects the API statelessly
func (this *MultiChainSecurityConfig) ApiSecurity() *HttpSecurity {
    return (&HttpSecurityBuilder{}).
        Match("/api/**"). // Only applies to /api paths
        Csrf().Disable().
        SessionCreationPolicy().Stateless().
        AuthorizedHTTPRequests().
            AnyRequest().Authenticated().
        And().
        Basic().
        Build()
}

// Chain 2: Protects the web UI statefully
func (this *MultiChainSecurityConfig) WebSecurity() *HttpSecurity {
    return (&HttpSecurityBuilder{}).
        Match("/web/**"). // Only applies to /web paths
        AuthorizedHTTPRequests().
            Paths("/web/public/**").PermitAll().
            AnyRequest().HasRole("USER").
        And().
        FormLogin(). // Secure via FormLogin instead of Basic
        Build()
}

```

## The Security Context

One of the biggest challenges in Go web development is accessing the authenticated user deep within your service layer. Often, developers resort to passing the user object or the HTTP Request context through dozens of function calls.

Rays Web Security solves this using `github.com/timandy/routine` to establish a **ThreadLocal SecurityContext** within its internal implementations.

### Accessing the Authenticated User

Whenever an authenticated request is being processed, the framework automatically binds the `Authentication` object to the current goroutine.

Because the interfaces are exposed in `pkg/core`, you can inject the `SecurityContextHolder` interface directly into any of your Beams and access the context from *anywhere* in your application without passing it down the call stack.

```go
package services

import (
    "fmt"
    . "github.com/BeamFoundry/rays-web-security/pkg/core"
    . "github.com/BeamFoundry/rays/pkg/core"
    . "github.com/BeamFoundry/rays/pkg/lang"
)

type OrderService struct {
    Service
    orderRepo             *OrderRepository      `@:"Inject"`
    securityContextHolder SecurityContextHolder `@:"Inject"` // Properly injected interface
}

func (this *OrderService) PlaceOrder(cart Cart) Error {

    // Retrieve the context using the injected holder for the current thread
    auth := this.securityContextHolder.GetContext().GetAuthentication()

    if auth == nil || !auth.IsAuthenticated() {
        return NewError("Unauthorized", "You must be logged in to place an order")
    }

    // Safely cast the principal back to your domain model
    currentUser := auth.GetPrincipal().(*models.User)

    fmt.Printf("User %s is placing an order for %v\n", currentUser.Email, cart.Total)

    // ... process order ...
    return nil
}

```
