// # Initialization
//
// This package should be imported from a main file, alongside rays :
//
//	package main
//
//	import (
//	  "github.com/BeamFoundry/rays"
//	  _ "github.com/BeamFoundry/rays-web-security"
//	)
//
// # Packages
//
// This project divides its code between the following packages :
//
//   - [github.com/BeamFoundry/rays-web-security/pkg/core]: Contains **all interfaces** (`UserDetails`, `PasswordEncoder`, `SecurityContextHolder`, etc.).
//   - [github.com/BeamFoundry/rays-web-security/pkg/config]: Contains the `HttpSecurityBuilder` types.
//   - [github.com/BeamFoundry/rays-web-security/pkg/auth]: Contains concrete `AuthenticationProvider` implementations.
//   - [github.com/BeamFoundry/rays-web-security/pkg/password]: Contains concrete `PasswordEncoder` implementations.
//   - [github.com/BeamFoundry/rays-web-security/pkg/rememberme]: Contains `RememberMeService` implementations.
//   - [github.com/BeamFoundry/rays-web-security/pkg/certs]: Contains TLS configuration providers and customizers for server, client, mTLS, CRL, and OCSP verification.
//   - [github.com/BeamFoundry/rays-web-security/pkg/testing]: Contains in-memory mock implementations for Ginkgo test suites.
package rays_web_security //nolint:revive // Ignoring package naming hint

import (
	_ "github.com/BeamFoundry/rays-web-security/internal/autoconfig" // Needed
)
