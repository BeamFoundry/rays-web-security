---
title: "2. Quickstart & Setup"
weight: 2
---

# Quickstart & Setup

To secure your application, you need to construct an `HttpSecurity` Beam. This tells the framework which endpoints require authentication and which are public.

## 📦 Installation

```bash
go get github.com/BeamFoundry/rays-web-security
```

## The Minimal Security Configuration

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

## The Entrypoint

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
