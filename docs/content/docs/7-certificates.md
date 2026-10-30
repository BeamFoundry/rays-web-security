---
title: "7. Certificates & TLS"
weight: 7
---

# Certificates & TLS Configuration

Modern enterprise web services require robust transport layer security. While web frameworks often provide basic TLS flags, real-world deployments frequently require:

- Automated certificate management via **ACME / Let's Encrypt**.
- Mutual TLS (**mTLS**) for zero-trust service-to-service communication.
- Real-time certificate validation via **Certificate Revocation Lists (CRL)** and **Online Certificate Status Protocol (OCSP)**.
- Unified, framework-agnostic `*tls.Config` generation.

The `pkg/certs` package provides modular, composable TLS providers and customizers built on Go's standard `crypto/tls` library and powered by `go-resty/resty` for network fetches.

---

## 📦 Core Interfaces & Helpers

The package separates configuration into **Providers** (which create a base `*tls.Config`) and **Customizers** (which mutate and augment an existing `*tls.Config`).

```go
package certs

import "crypto/tls"

// ServerTLSProvider produces a server-side *tls.Config.
type ServerTLSProvider interface {
    ProvideServerTLS() (*tls.Config, error)
}

// ServerTLSCustomizer mutates an existing server *tls.Config.
type ServerTLSCustomizer interface {
    CustomizeServerTLS(*tls.Config) error
}

// ClientTLSProvider produces a client-side *tls.Config.
type ClientTLSProvider interface {
    ProvideClientTLS() (*tls.Config, error)
}

// ClientTLSCustomizer mutates an existing client *tls.Config.
type ClientTLSCustomizer interface {
    CustomizeClientTLS(*tls.Config) error
}
```

### Chaining with `ConfigureServerTLS` and `ConfigureClientTLS`

You compose a provider with any number of customizers using the functional configuration helpers:

```go
tlsConfig, err := certs.ConfigureServerTLS(serverProvider, mtlsCustomizer, crlCustomizer)
if err != nil {
    log.Fatalf("failed to configure server TLS: %v", err)
}
```

---

## 🔒 Server TLS Configuration

### 1. `ServerCertificateProvider` (Static Certificates)

Use `ServerCertificateProvider` when loading certificates from local PEM files or memory strings:

```go
package main

import (
    "crypto/tls"
    "github.com/BeamFoundry/rays-web-security/pkg/certs"
)

func createServerTLS() (*tls.Config, error) {
    provider := certs.ServerCertificateProvider{
        CertFile:   "/etc/ssl/certs/server.crt",
        KeyFile:    "/etc/ssl/private/server.key",
        MinVersion: tls.VersionTLS13, // Defaults to TLS 1.2 if omitted
    }

    return certs.ConfigureServerTLS(provider)
}
```

You can also pass raw PEM strings directly using `Certificate.Certificate` and `Certificate.PrivateKey`.

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
        Manager:    manager,
        MinVersion: tls.VersionTLS13,
    }

    return certs.ConfigureServerTLS(provider)
}
```

---

## 🤝 Mutual TLS (mTLS)

To require and verify client certificates on incoming connections, apply `MutualTLSCustomizer`:

```go
package main

import (
    "github.com/BeamFoundry/rays-web-security/pkg/certs"
)

func createMTLSServer() (*tls.Config, error) {
    serverProvider := certs.ServerCertificateProvider{
        CertFile: "/etc/ssl/certs/server.crt",
        KeyFile:  "/etc/ssl/private/server.key",
    }

    mtlsCustomizer := certs.MutualTLSCustomizer{
        ClientCertFiles: []string{
            "/etc/ssl/certs/client-ca.crt",
        },
    }

    // Configures ClientAuth: tls.RequireAndVerifyClientCert and adds the CA to ClientCAs
    return certs.ConfigureServerTLS(serverProvider, mtlsCustomizer)
}
```

---

## 📜 Certificate Revocation List (CRL) Verification

To prevent revoked client certificates from authenticating, chain `MutualTLSWithCRLCustomizer`. It installs a secure `VerifyPeerCertificate` callback that checks client certificates against a CRL:

```go
package main

import (
    "time"
    "github.com/BeamFoundry/rays-web-security/pkg/certs"
)

func createServerWithCRL() (*tls.Config, error) {
    serverProvider := certs.ServerCertificateProvider{
        CertFile: "/etc/ssl/certs/server.crt",
        KeyFile:  "/etc/ssl/private/server.key",
    }

    crlCustomizer := certs.MutualTLSWithCRLCustomizer{
        // 1. Can be a local file path: "/etc/ssl/crl/ca.crl"
        // 2. Can be an HTTP/HTTPS URL: "https://crl.example.com/revoked.crl"
        // 3. Or leave empty to auto-discover via CA cert CRLDistributionPoints
        RevocationList: "https://crl.example.com/revoked.crl",
        Timeout:        10 * time.Second, // Defaults to 5s if omitted
    }

    return certs.ConfigureServerTLS(serverProvider, crlCustomizer)
}
```

### CRL Features:
* **Multiple Sources:** Supports local file paths, inline PEM strings, remote `http://` or `https://` URLs, and fallback to the issuer certificate's `CRLDistributionPoints` extension.
* **Format Agnostic:** Automatically handles both PEM-encoded CRLs and binary DER-encoded CRLs.
* **HTTPS Support:** When fetching CRL over HTTPS, provide a `TLSProvider` to supply client certificates or custom root CAs for the fetch request.

---

## ⚡ Online Certificate Status Protocol (OCSP) Verification

OCSP enables real-time verification of certificate revocation without downloading large CRL files:

```go
package main

import (
    "time"
    "github.com/BeamFoundry/rays-web-security/pkg/certs"
)

func createServerWithOCSP() (*tls.Config, error) {
    serverProvider := certs.ServerCertificateProvider{
        CertFile: "/etc/ssl/certs/server.crt",
        KeyFile:  "/etc/ssl/private/server.key",
    }

    ocspCustomizer := certs.MutualTLSWithOCSPCustomizer{
        // Explicit responder URL, or leave empty to auto-discover via certificate AIA OCSPServer
        OCSPServer: "http://ocsp.example.com",
        Timeout:    5 * time.Second,
    }

    return certs.ConfigureServerTLS(serverProvider, ocspCustomizer)
}
```

### OCSP Features:
* **Auto-Discovery:** Automatically falls back to the certificate's Authority Information Access (`OCSPServer`) extension if no explicit `OCSPServer` is configured.
* **Resty-Powered Client:** Queries the OCSP responder using `resty`, handling ASN.1 DER request serialization and response verification.
* **Strict Revocation Detection:** Returns `ErrCertificateRevoked` for revoked certificates and `ErrCertificateUnknownOCSP` for unknown certificate statuses.

---

## 🌐 Client TLS Configuration

When your application initiates outgoing TLS or mTLS connections (e.g., using `net/http` or `go-resty/resty`), use `ClientCertificateProvider`:

```go
package main

import (
    "crypto/tls"
    "github.com/BeamFoundry/rays-web-security/pkg/certs"
    "github.com/go-resty/resty/v2"
)

func createSecureClient() (*resty.Client, error) {
    clientTLSProvider := certs.ClientCertificateProvider{
        // Custom CA bundle (falls back to system root pool if omitted)
        CAFiles: []string{"/etc/ssl/certs/internal-ca.crt"},

        // Client credentials for outgoing mTLS
        CertFile: "/etc/ssl/certs/client.crt",
        KeyFile:  "/etc/ssl/private/client.key",

        MinVersion: tls.VersionTLS13,
    }

    tlsConfig, err := certs.ConfigureClientTLS(clientTLSProvider)
    if err != nil {
        return nil, err
    }

    client := resty.New()
    client.SetTLSClientConfig(tlsConfig)
    return client, nil
}
```

---

## 🧩 Complete Server Example: ACME + mTLS + OCSP

Here is a full production example configuring an HTTPS server with automated Let's Encrypt certificates, mandatory client certificate verification, and real-time OCSP validation:

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
        Manager: &autocert.Manager{
            Prompt:     autocert.AcceptTOS,
            HostPolicy: autocert.HostWhitelist("secure.example.com"),
            Cache:      autocert.DirCache("/var/cache/autocert"),
            Email:      "admin@example.com",
        },
        MinVersion: tls.VersionTLS13,
    }

    // 2. mTLS Customizer
    mtls := certs.MutualTLSCustomizer{
        ClientCertFiles: []string{"/etc/ssl/certs/client-ca.crt"},
    }

    // 3. OCSP Customizer
    ocsp := certs.MutualTLSWithOCSPCustomizer{
        Timeout: 3 * time.Second,
    }

    // 4. Assemble *tls.Config
    tlsConfig, err := certs.ConfigureServerTLS(acmeProvider, mtls, ocsp)
    if err != nil {
        panic(err)
    }

    server := &http.Server{
        Addr:      ":8443",
        TLSConfig: tlsConfig,
    }

    if err := server.ListenAndServeTLS("", ""); err != nil {
        panic(err)
    }
}
```
