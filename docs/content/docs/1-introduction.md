---
title: "1. Introduction"
weight: 1
---

# Introduction & Architecture

Securing enterprise applications often leads to messy, scattered middleware across various routers.
Rays Web Security centralizes this logic into declarative **Security Filter Chains**.

## Core Architectural Features

1. **Declarative Authorization:** Define endpoint security rules using a highly expressive `HttpSecurityBuilder`
  rather than imperative `if/else` blocks inside your handlers.
2. **Pluggable Authentication:** Easily swap out how users are authenticated by implementing the
  `AuthenticationProvider` or `UserDetailsService` interfaces.
3. **ThreadLocal Context:** Web Security utilizes `github.com/timandy/routine` to store the currently
  authenticated user in a ThreadLocal `SecurityContext`. Your deeper service layers can retrieve the
  user without needing the HTTP request object passed down.
4. **IoC Native Auto-Configuration:** The framework provides default security implementations out of
  the box, which you can easily override by defining your own Beams.

## 📦 Package Structure & Imports

To prevent circular dependencies and maintain clean boundaries, Rays Web Security is split into distinct packages:

*   `github.com/BeamFoundry/rays-web-security`: The root package. You underscore-import this in `main.go` to
  trigger the internal auto-configurations.
*   `.../pkg/core`: Contains **all interfaces** (`UserDetails`, `PasswordEncoder`, `SecurityContextHolder`, etc.).
*   `.../pkg/config`: Contains the `HttpSecurityBuilder` types.
*   `.../pkg/auth`: Contains concrete `AuthenticationProvider` implementations.
*   `.../pkg/password`: Contains concrete `PasswordEncoder` implementations.
*   `.../pkg/rememberme`: Contains `RememberMeService` implementations.
*   `.../pkg/testing`: Contains in-memory mock implementations for Ginkgo test suites.

## 🧹 Simplifying with Dot Imports
To keep your domain code clean, it is highly recommended to use Go's dot import feature for the core and config packages:

```go
import (
    . "github.com/BeamFoundry/rays-web-security/pkg/core"
    . "github.com/BeamFoundry/rays-web-security/pkg/config"
)
```
