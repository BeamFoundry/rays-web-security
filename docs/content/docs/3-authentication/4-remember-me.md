---
title: "Remember Me"
weight: 4
---

# 4. Remember Me Services

To keep users logged in across browser sessions without relying solely on long-lived session cookies, you can leverage the `RememberMeService` interface.

The framework provides a `TokenBasedRememberMeService` in `pkg/rememberme`. For a robust enterprise configuration, you should avoid hardcoding secrets and instead use Rays' `ConfigurationProperties` to load your configuration from YAML.

## Configuration Options & Defaults

The `TokenBasedRememberMeService` provides several fluent builder methods to customize its behavior:

| Method | Default Value | Description |
| :--- | :--- | :--- |
| `WithParameter()` | "remember-me" | The HTML form input checked to determine if the cookie should be set. |
| `WithCookieName()` | "remember-me" | The name of the cookie sent to the browser. |
| `WithCookieDomain()` | "" | The domain restriction for the cookie. |
| `WithCookieSecure()` | false | Whether the secure (HTTPS-only) bit should be set on the cookie. |
| `WithValidity()` | 1209600 (14 days) | How long, in seconds, the cookie will be valid. |

## Example: Externalized Configuration

First, define your YAML configuration. We explicitly provide the default values here for reference:

```yaml
# application.yaml
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
