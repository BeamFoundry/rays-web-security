---
title: "Form Login"
weight: 2
---

# Form Login & Remember Me

If you are building a traditional web application with server-rendered HTML views (instead of a stateless API), you will likely want to use **Form Login** instead of Basic Authentication.

The `FormLogin()` builder exposes several methods to fully customize the authentication flow. 

### Configuration Defaults

If you call `.FormLogin()` without any additional chained configuration, the framework applies the following defaults automatically:

| Method | Default Value | Description |
| :--- | :--- | :--- |
| `Username()` | "username" | The HTML form field name for the user's username. |
| `Password()` | "password" | The HTML form field name for the user's password. |
| `LoginPath()` | "/login" | The path where the login hook is registered. |
| `LogoutPath()` | "/logout" | The path where the logout hook is registered. |
| `ViewName()` | "login" | The template view name rendered for the login form. |
| `DefaultSuccessURL()` | "/" | The default URL to redirect to upon successful login. |

You can selectively override any of these defaults, serve a specific login view, and optionally integrate a `RememberMeService`:

```go
package configurations

import (
    . "github.com/BeamFoundry/rays-web-security/pkg/config"
    . "github.com/BeamFoundry/rays-web-security/pkg/core"
    . "github.com/BeamFoundry/rays/pkg/core"
)

type SecurityConfig struct {
    Configuration
}

// The HttpSecurity Beam provider configuring Form Login and Remember Me
func (this *SecurityConfig) HttpSecurity(
    that struct {
        rememberme RememberMeService `@:"Inject"`
    },
) *HttpSecurity {
    
    return (&HttpSecurityBuilder{}).
        AuthorizedHTTPRequests().
            Paths("/profile").Authenticated().
            Paths("/todolists**").HasRole("USER").
            Paths("/admin/**").HasRole("ADMIN").
            Paths("/static/**", "/.well-known/**").PermitAll().
        And().
            AnyRequest().DenyAll().
        FormLogin().
            Username("user_email").          // Custom HTML field name for username
            Password("user_password").       // Custom HTML field name for password
            LoginPath("/auth/login").        // Custom POST endpoint for the login form
            LogoutPath("/auth/logout").      // Custom POST endpoint for logout
            ViewName("views/login").         // The template to render for the login page
            DefaultSuccessURL("/dashboard"). // Where to redirect if no prior saved URL exists
        And().
            RememberMe(that.rememberme).
        Build()
}

var _, _ = any(&SecurityConfig{}).(Stereotype)
```

> **Smart Redirects:** If an unauthenticated user attempts to access a protected page, the framework saves their intended destination in their session. Upon successful login, they will be automatically redirected to that saved URL rather than the `DefaultSuccessURL`.
