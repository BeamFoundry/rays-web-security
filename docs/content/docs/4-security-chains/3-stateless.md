---
title: "Stateless APIs"
weight: 3
---

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
