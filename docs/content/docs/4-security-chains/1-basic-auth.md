---
title: "Basic Authentication"
weight: 1
---

# Basic Authentication

For APIs and simple services without a frontend interface, you will typically use **Basic Authentication** (passing credentials via the HTTP `Authorization` header).

You can enable this by calling the `Basic()` method on the `HttpSecurityBuilder` before building the final security configuration.

```go
package configurations

import (
    . "github.com/BeamFoundry/rays-web-security/pkg/config"
    . "github.com/BeamFoundry/rays/pkg/core"
)

type BasicSecurityConfig struct {
    Configuration
}

// The HttpSecurity Beam provider. 
func (this *BasicSecurityConfig) HttpSecurity() *HttpSecurity {
    return (&HttpSecurityBuilder{}).
        AuthorizedHTTPRequests().
            Paths("/api/public/**").PermitAll().
            AnyRequest().Authenticated().
        And().
        Basic(). // Secure all authenticated endpoints via BasicAuth
        Build()
}

var _, _ = any(&BasicSecurityConfig{}).(Stereotype)
```
