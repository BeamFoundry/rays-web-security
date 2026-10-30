---
title: "7. Certificates & TLS"
weight: 7
---

# Certificates & TLS Configuration

Modern enterprise web services require robust transport layer security. While web frameworks often provide basic TLS flags, real-world deployments frequently require:

- Automated certificate management via **ACME / Let's Encrypt**.
- Mutual TLS (**mTLS**) for zero-trust service-to-service communication.
- Certificate validation via **Certificate Revocation Lists (CRL)**, which are loaded during TLS configuration and remain in use until the server reloads the TLS configuration with an updated CRL.
- Real-time certificate validation via **Online Certificate Status Protocol (OCSP)**.
- Unified, framework-agnostic `*tls.Config` generation.

The `pkg/certs` package provides modular, composable TLS providers and customizers built on Go's standard `crypto/tls` library and powered by `go-resty/resty` for network fetches.

---

## 📦 Core Interfaces & Helpers

The package separates configuration into **Providers** (which create a base `*tls.Config`) and **Customizers** (which mutate and augment an existing server `*tls.Config`).

```go
package certs

import "crypto/tls"

// ServerTLSProvider produces a server-side *tls.Config.
type ServerTLSProvider interface {
    ProvideServerTLS() (*tls.Config, error)
}

// ServerTLSCustomizer mutates an existing server *tls.Config.
type ServerTLSCustomizer interface {
    CustomizeServerTLS(config *tls.Config) error
}

// ClientTLSProvider produces a client-side *tls.Config.
type ClientTLSProvider interface {
    ProvideClientTLS() (*tls.Config, error)
}
```

### Server vs. Client Configuration Helpers

- **`ConfigureServerTLS`**: Accepts a `ServerTLSProvider` and any number of `ServerTLSCustomizer` hooks to compose and mutate the server configuration:
  ```go
  tlsConfig, err := certs.ConfigureServerTLS(&serverProvider, &mtlsCustomizer, &crlCustomizer)
  if err != nil {
      log.Fatalf("failed to configure server TLS: %v", err)
  }
  ```
- **`ConfigureClientTLS`**: Accepts only a `ClientTLSProvider`. Client options (such as custom root CAs, system certificate inheritance, and client credentials) are configured directly on the provider struct without customizer hooks:
  ```go
  tlsConfig, err := certs.ConfigureClientTLS(&clientProvider)
  if err != nil {
      log.Fatalf("failed to configure client TLS: %v", err)
  }
  ```

---

## 🔒 Server TLS Configuration

### 1. `ServerCertificateProvider` (Static Certificates)

Use `ServerCertificateProvider` when loading certificates from local PEM files or memory strings. Pointer references should be passed when invoking `ConfigureServerTLS`:

```go
package main

import (
    "crypto/tls"
    "log"

    "github.com/BeamFoundry/rays-web-security/pkg/certs"
)

func createServerTLS() (*tls.Config, error) {
    provider := certs.ServerCertificateProvider{
        CertFile:      "/etc/ssl/certs/server.crt",
        CertKeyFile:   "/etc/ssl/private/server.key",
        TLSMinVersion: tls.VersionTLS13, // Defaults to tls.VersionTLS12 if omitted
    }

    return certs.ConfigureServerTLS(&provider)
}
```

You can also pass raw PEM content (combining certificate, intermediate CAs, and private key) directly into `Certificate`.

### 2. `ACMECertificateProvider` (Let's Encrypt / ACME)

For automatic issuance and renewal of TLS certificates via Let's Encrypt or any ACME-compliant directory, use `ACMECertificateProvider`:

```go
package main

import (
    "crypto/tls"

    "github.com/BeamFoundry/rays-web-security/pkg/certs"
    "golang.org/x/crypto/acme/autocert"
)

func createAcmeTLS() (*tls.Config, error) {
    manager := &autocert.Manager{
        Prompt:     autocert.AcceptTOS,
        HostPolicy: autocert.HostWhitelist("api.example.com", "auth.example.com"),
        Cache:      autocert.DirCache("/var/cache/acme"),
        Email:      "security@example.com",
    }

    provider := certs.ACMECertificateProvider{
        AutoCertManager: manager,
        TLSMinVersion:   tls.VersionTLS13,
    }

    return certs.ConfigureServerTLS(&provider)
}
```

---

## 🤝 Mutual TLS (mTLS)

To require and verify client certificates on incoming connections, apply `MutualTLSCustomizer`. Supply the client CA certificate path or inline PEM in the `Certificate` field:

```go
package main

import (
    "crypto/tls"

    "github.com/BeamFoundry/rays-web-security/pkg/certs"
)

func createMTLSServer() (*tls.Config, error) {
    serverProvider := certs.ServerCertificateProvider{
        CertFile:    "/etc/ssl/certs/server.crt",
        CertKeyFile: "/etc/ssl/private/server.key",
    }

    mtlsCustomizer := certs.MutualTLSCustomizer{
        Certificate: "/etc/ssl/certs/client-ca.crt",
    }

    // Configures ClientAuth: tls.RequireAndVerifyClientCert and adds the CA to ClientCAs
    return certs.ConfigureServerTLS(&serverProvider, &mtlsCustomizer)
}
```

---

## 📜 Certificate Revocation List (CRL) Verification

To prevent revoked client certificates from authenticating, chain `MutualTLSWithCRLCustomizer`. The client CA certificate must be configured in `Certificate` so the customizer can verify the CRL signature and install its `VerifyConnection` callback:

```go
package main

import (
    "crypto/tls"
    "time"

    "github.com/BeamFoundry/rays-web-security/pkg/certs"
)

func createServerWithCRL() (*tls.Config, error) {
    serverProvider := certs.ServerCertificateProvider{
        CertFile:    "/etc/ssl/certs/server.crt",
        CertKeyFile: "/etc/ssl/private/server.key",
    }

    crlCustomizer := certs.MutualTLSWithCRLCustomizer{
        Certificate:    "/etc/ssl/certs/client-ca.crt",
        RevocationList: "https://crl.example.com/revoked.crl",
        Timeout:        10 * time.Second, // Defaults to 10s if omitted
    }

    return certs.ConfigureServerTLS(&serverProvider, &crlCustomizer)
}
```

> [!WARNING]
> When `RevocationList` is left empty, the customizer attempts to auto-discover CRL endpoints from the client CA certificate's `CRLDistributionPoints`. If discovery finds no usable list or if all fetch attempts fail, configuration succeeds without installing a revocation callback, and revoked certificates may pass standard chain verification. For deployments requiring strict revocation guarantees, explicitly configure `RevocationList`.

### CRL Features:
* **Multiple Sources:** Supports local file paths, inline PEM strings, remote `http://` or `https://` URLs, and fallback to the issuer certificate's `CRLDistributionPoints` extension.
* **PEM Encoding Required:** Both local and remote CRLs must be PEM-encoded (containing a `-----BEGIN X509 CRL-----` block). Raw binary DER-encoded CRLs are not supported.
* **HTTPS Support:** When fetching CRL over HTTPS, provide a `TLSProvider` to supply client certificates or custom root CAs for the fetch request.
* **Validation on Connection:** Runs inside `VerifyConnection`, ensuring revocation checks occur on both full handshakes and resumed TLS sessions.

---

## ⚡ Online Certificate Status Protocol (OCSP) Verification

OCSP enables real-time verification of certificate revocation without downloading entire CRL files. Set the client CA in `Certificate` so the customizer can construct and verify OCSP requests:

```go
package main

import (
    "crypto/tls"
    "time"

    "github.com/BeamFoundry/rays-web-security/pkg/certs"
)

func createServerWithOCSP() (*tls.Config, error) {
    serverProvider := certs.ServerCertificateProvider{
        CertFile:    "/etc/ssl/certs/server.crt",
        CertKeyFile: "/etc/ssl/private/server.key",
    }

    ocspCustomizer := certs.MutualTLSWithOCSPCustomizer{
        Certificate: "/etc/ssl/certs/client-ca.crt",
        OCSPServer:  "http://ocsp.example.com",
        Timeout:     5 * time.Second,
    }

    return certs.ConfigureServerTLS(&serverProvider, &ocspCustomizer)
}
```

> [!WARNING]
> When `OCSPServer` is left empty, the customizer attempts to discover the responder from the certificate's Authority Information Access (`OCSPServer`) extension. If no responder is found, configuration succeeds without installing an OCSP verification callback. Explicitly specify `OCSPServer` when OCSP validation is mandatory.

### OCSP Features:
* **Delegated Responder Validation:** Delegated OCSP responder certificates must be signed by the CA and include the `OCSPSigning` extended key usage.
* **Freshness & Expiry Checks:** Rejects responses whose `ThisUpdate` exceeds `MaxResponseAge` (default 24h). When `NextUpdate` is absent, treats the response validity as expiring at `ThisUpdate + MaxResponseAge`.
* **In-Memory Response Caching:** Caches validated OCSP responses keyed by certificate serial number until `NextUpdate` expires, minimizing network round-trips while preserving fail-closed behavior on responder errors.
* **Resumption Protection:** Runs inside `VerifyConnection` to validate peer certificates on new and resumed TLS sessions alike.

---

## 🌐 Client TLS Configuration

When your application initiates outgoing TLS or mTLS connections (e.g., using `go-resty/resty`), use `ClientCertificateProvider`:

```go
package main

import (
    "crypto/tls"

    "github.com/BeamFoundry/rays-web-security/pkg/certs"
    "github.com/go-resty/resty/v2"
)

func createSecureClient() (*resty.Client, error) {
    clientTLSProvider := certs.ClientCertificateProvider{
        // Custom CA certificate file or PEM string
        RootCertificates: "/etc/ssl/certs/internal-ca.crt",

        // Explicitly include host system root certificates alongside custom roots
        IncludeSystemCertificates: true,

        // Client certificate and key for outgoing mTLS (PEM file or string with cert + key)
        Certificate: "/etc/ssl/certs/client-fullchain.pem",

        TLSMinVersion: tls.VersionTLS13,
    }

    tlsConfig, err := certs.ConfigureClientTLS(&clientTLSProvider)
    if err != nil {
        return nil, err
    }

    client := resty.New()
    client.SetTLSClientConfig(tlsConfig)
    return client, nil
}
```

> [!NOTE]
> Omitting `RootCertificates` creates an empty root pool when client credentials are configured. There is no automatic fallback to the host system root pool; set `IncludeSystemCertificates: true` to include system-trusted root certificates.

---

## 🧩 Complete Server Example: ACME + mTLS + OCSP

Here is a full production example configuring an HTTPS server on port 443 with automated Let's Encrypt certificates, mandatory client certificate verification, and real-time OCSP validation:

```go
package main

import (
    "crypto/tls"
    "net/http"
    "time"

    "github.com/BeamFoundry/rays-web-security/pkg/certs"
    "golang.org/x/crypto/acme/autocert"
)

func main() {
    // 1. Base ACME Provider
    acmeProvider := certs.ACMECertificateProvider{
        AutoCertManager: &autocert.Manager{
            Prompt:     autocert.AcceptTOS,
            HostPolicy: autocert.HostWhitelist("secure.example.com"),
            Cache:      autocert.DirCache("/var/cache/autocert"),
            Email:      "admin@example.com",
        },
        TLSMinVersion: tls.VersionTLS13,
    }

    // 2. mTLS Customizer
    mtls := certs.MutualTLSCustomizer{
        Certificate: "/etc/ssl/certs/client-ca.crt",
    }

    // 3. OCSP Customizer
    ocsp := certs.MutualTLSWithOCSPCustomizer{
        Certificate: "/etc/ssl/certs/client-ca.crt",
        Timeout:     3 * time.Second,
    }

    // 4. Assemble *tls.Config using pointers
    tlsConfig, err := certs.ConfigureServerTLS(&acmeProvider, &mtls, &ocsp)
    if err != nil {
        panic(err)
    }

    // 5. ACME TLS-ALPN-01 challenges must reach the server on port 443
    server := &http.Server{
        Addr:      ":443",
        TLSConfig: tlsConfig,
    }

    if err := server.ListenAndServeTLS("", ""); err != nil {
        panic(err)
    }
}
```
