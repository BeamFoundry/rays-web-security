---
title: "4. Security Chains"
weight: 4
bookCollapseSection: false
---

# Security Chains & Authorization

Now that you have configured how users authenticate, you must define the `HttpSecurity` rules to intercept incoming HTTP requests and determine if they should be allowed to proceed.

## The `HttpSecurityBuilder`

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

### AntPath Style Matching

When securing endpoints using `Paths(...)` (or using `Match()` for multiple chains), Rays Web Security uses **AntPath style matching**. This provides highly expressive wildcard routing:

*   `?` matches exactly one character.
*   `*` matches zero or more characters within a *single* path segment.
*   `**` matches zero or more *path segments*.

**Examples:**
*   `/api/products/*` matches `/api/products/123` but **not** `/api/products/123/reviews`.
*   `/api/admin/**` matches `/api/admin`, `/api/admin/users`, and `/api/admin/users/delete`.

## Authorization Policies

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

## Multiple Security Chains

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

# Stateless vs. Stateful Sessions

By default, Rays Web Security assumes you are building a stateful web application (using session cookies). If you are building a modern API (e.g., React, Vue, Mobile App) that uses stateless tokens, you must tell the framework to operate in a stateless manner.

You can do this by using the `Csrf().Disable()` and `SessionCreationPolicy()` builder methods.

## Session Creation Policies

The `SessionCreationPolicy()` builder provides several options to control when the framework provisions a session:

*   **`.Default()` / `.IfRequired()`:** Rays will create a Session only if required (the default behavior).
*   **`.Always()`:** Rays will always create a Session.
*   **`.Never()`:** Rays will never proactively create a Session, but will use one if it already exists.
*   **`.Stateless()`:** Rays will strictly not configure or use a Session (ideal for JWT APIs).

### Example: Stateless Configuration

```go
func (this *RouteSecurityConfig) HttpSecurity() *HttpSecurity {
    return (&HttpSecurityBuilder{}).
        Csrf().Disable(). // CSRF protection is generally not needed for stateless APIs
        SessionCreationPolicy().Stateless(). // Fluently instruct the framework to be stateless
        AuthorizedHTTPRequests().
            Paths("/api/public/**").PermitAll().
        And().
            AnyRequest().Authenticated().
        Basic().
        Build()
}
```
