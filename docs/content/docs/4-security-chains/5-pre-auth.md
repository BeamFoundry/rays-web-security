---
title: "Pre-Authentication"
weight: 5
---

# Pre-Authentication

In enterprise architectures, authentication is often offloaded to an external infrastructure component before the request ever reaches your application:

*   **Reverse Proxies & API Gateways**: NGINX, Apache, Envoy, or Traefik validating client tokens or mutual TLS (mTLS) and injecting identity headers (e.g. `X-Remote-User`, `X-Forwarded-User`).
*   **Identity & Access Gateways**: Cloudflare Access, OAuth2-Proxy, AWS ALB, Google Cloud IAP, or CA SiteMinder asserting verified identity.
*   **Direct Mutual TLS (mTLS)**: Clients authenticating with an X.509 client certificate directly terminated by the application.

Rays Web Security provides first-class support for **Pre-Authentication**, inspired by Spring Security's pre-authentication model.

## Enabling Pre-Authentication

Enable and configure pre-authentication by invoking `.PreAuth()` on your `HttpSecurityBuilder`:

```go
package configurations

import (
    . "github.com/BeamFoundry/rays-web-security/pkg/config"
    . "github.com/BeamFoundry/rays/pkg/core"
)

type SecurityConfig struct {
    Configuration
}

func (this *SecurityConfig) HttpSecurity() *HttpSecurity {
    return (&HttpSecurityBuilder{}).
        AuthorizedHTTPRequests().
            Paths("/api/admin/**").HasRole("ADMIN").
            Paths("/api/**").Authenticated().
        And().
        PreAuth().
            PrincipalHeader("X-Remote-User").
            RolesHeader("X-Remote-Roles").
            RolesDelimiter(",").
        And().
        SessionCreationPolicy().Stateless().
        Build()
}

var _, _ = any(&SecurityConfig{}).(Stereotype)
```

## Configuration Options

The `PreAuth()` builder provides the following methods:

| Method | Default Value | Description |
| :--- | :--- | :--- |
| `PrincipalHeader(string)` | `"X-Remote-User"` | HTTP request header used to extract the user principal (username/identity). |
| `CredentialsHeader(string)` | `""` (empty) | Optional HTTP header to extract pre-authenticated credentials (e.g. certificate or proxy token). |
| `RolesHeader(string)` | `""` (empty) | Optional HTTP header to extract roles or granted authorities. |
| `RolesDelimiter(string)` | `","` | Delimiter used to split multiple roles in `RolesHeader`. |
| `AllowMtlsFallback(bool)` | `true` | When `true`, falls back to direct mTLS client certificates if no valid header identity is present. |
| `TrustedProxies(...string)` | `[]` (empty) | List of allow-listed proxy identifiers (CommonName or Subject) allowed to forward identity headers. |
| `ExceptionOnMissing(bool)` | `false` | When `true`, immediately rejects requests with `403 Forbidden` if pre-authenticated credentials are missing, rather than proceeding down the filter chain. |

## Security & Header Spoofing Protection

Pre-authentication trusts the identity forwarded in HTTP headers. If an untrusted client can send requests directly to your backend, they could forge `X-Remote-User` and impersonate any user.

Rays Web Security includes built-in safeguards to prevent header spoofing:

### 1. Mutual Exclusivity Between Headers & mTLS

When a client establishes a direct connection with a verified mTLS certificate, an untrusted request header cannot override the verified mTLS identity. The framework enforces direct mTLS identity and ignores spoofed user headers.

### 2. Trusted Proxy Restrictions (`TrustedProxies`)

When your backend terminates mTLS connections from both reverse proxies and direct clients, you can configure `TrustedProxies`:

```go
func (this *SecurityConfig) HttpSecurity() *HttpSecurity {
    return (&HttpSecurityBuilder{}).
        AuthorizedHTTPRequests().
            AnyRequest().Authenticated().
        And().
        PreAuth().
            PrincipalHeader("X-Remote-User").
            TrustedProxies("proxy.internal.net", "CN=gateway.infra").
            AllowMtlsFallback(true).
        And().
        Build()
}
```

*   **Verified Proxy**: If the incoming connection presents a verified mTLS certificate matching `TrustedProxies`, the header `X-Remote-User` is accepted.
*   **Direct Client**: If the client connects with their own mTLS certificate (not in `TrustedProxies`), header override is blocked and their own certificate identity is used.
*   **Unverified Connection**: Plaintext or unverified connections cannot assert user identity via headers when trusted proxies are configured.

### 3. Role Stripping on mTLS Fallback

When authentication falls back to direct mTLS client certificates, any request-supplied header roles (`RolesHeader`) are automatically cleared. Authorities must be derived from the verified certificate or loaded via an `AuthenticationUserDetailsService`.

## User Details & Authority Mapping

Once a principal is extracted (from headers or mTLS), authentication is processed by an `AuthenticationProvider` delegating to an `AuthenticationUserDetailsService`:

```go
type AuthenticationUserDetailsService interface {
    LoadUserDetails(token Authentication) (UserDetails, AuthenticationException)
}
```

Rays Web Security includes two built-in implementations:

1.  **`PreAuthenticatedGrantedAuthoritiesUserDetailsService`**: Creates a `UserDetails` instance using the principal string and authorities parsed directly from the pre-authentication token / roles header.
2.  **`UserDetailsByNameServiceWrapper`**: Adapts an existing `UserDetailsService` (such as a database or in-memory user repository) to load full account details and permissions for the pre-authenticated username.

By default, `internal/autoconfig` automatically configures a `PreAuthenticatedAuthenticationProvider` and provides a default `AuthenticationUserDetailsService`:
* If a `UserDetailsService` beam is found in the IoC container, it is automatically wrapped using `UserDetailsByNameServiceWrapper`.
* If no `UserDetailsService` beam is present, it defaults to `PreAuthenticatedGrantedAuthoritiesUserDetailsService`.

### Registering a Custom `AuthenticationUserDetailsService`

To map pre-authenticated identities to database users or custom permissions, register an `AuthenticationUserDetailsService` Beam in your configuration:

```go
package configurations

import (
    . "github.com/BeamFoundry/rays-web-security/pkg/auth"
    . "github.com/BeamFoundry/rays-web-security/pkg/core"
    . "github.com/BeamFoundry/rays/pkg/core"
)

type PreAuthConfig struct {
    Configuration
}

func (this *PreAuthConfig) PreAuthUserDetailsService(
    that struct {
        userDetailsService UserDetailsService `@:"Inject"`
    },
) AuthenticationUserDetailsService {
    return UserDetailsByNameServiceWrapper{}.New(that.userDetailsService)
}

var _, _ = any(&PreAuthConfig{}).(Stereotype)
```
