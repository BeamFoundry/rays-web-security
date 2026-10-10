---
title: "6. Testing"
weight: 6
---

# Testing

Testing secured applications often requires mocking the user database so you don't have to spin up a real database just to test authorization logic. To complement the core Rays testing framework, Rays Web Security provides a `pkg/testing` package containing in-memory implementations.

## The InMemoryUserDetailsManager

The `InMemoryUserDetailsManager` allows you to rapidly configure a `UserDetailsService` populated with test users. It automatically encodes the plaintext passwords you provide using the injected `PasswordEncoder`.

These users are stored as `InMemoryUser` structs, which fully implement the `UserDetails` interface.

### Test Configuration Example

Here is how you can define a test configuration that provisions an admin and a standard user for your test suites:

```go
package tests

import (
    . "github.com/BeamFoundry/rays-web-security/pkg/core"
    . "github.com/BeamFoundry/rays-web-security/pkg/testing"
    . "github.com/BeamFoundry/rays/pkg/core"
)

type UserDetailsServiceConfiguration struct {
    Configuration
}

func (this *UserDetailsServiceConfiguration) UserDetailsService(
    that struct {
        passwordEncoder PasswordEncoder `@:"Inject"`
    },
) UserDetailsService {
    
    // Initialize the in-memory manager with the active password encoder
    userDetailsService := InMemoryUserDetailsManager{}.New(that.passwordEncoder)
    
    // Build a standard user
    userDetailsService.NewUser().
        WithUsername("user").
        WithPassword("user").
        WithAuthorities([]GrantedAuthority{Authority("ROLE_USER"), Authority("ROLE_PRIVILEGED")}).
        Build()
        
    // Build an admin user
    userDetailsService.NewUser().
        WithUsername("admin").
        WithPassword("admin").
        WithAuthorities([]GrantedAuthority{Authority("ROLE_USER"), Authority("ROLE_ADMIN")}).
        Build()
        
    return userDetailsService
}

var _, _ = any(&UserDetailsServiceConfiguration{}).(Stereotype)
```

### Integration with Ginkgo

You can easily load this mock configuration into your Rays `TestingContainer` during your Ginkgo test setup. Make sure to dot-import `github.com/BeamFoundry/rays/pkg/testing` to access `GetContainer()` and `AddBeamFor()`, which automatically hooks into Ginkgo to reset the container state between tests.

For maximum flexibility, initialize the container *inside* the `It` block rather than the `BeforeEach` block. This allows you to add specific Beams on a per-test basis before the container wires them up.

```go
import (
    . "github.com/onsi/ginkgo/v2"
    . "github.com/onsi/gomega"
    
    . "github.com/BeamFoundry/rays/pkg/testing"
)

var _ = Describe("SecurityFilterChain", func() {
    
    BeforeEach(func() {
        // Register the mock user details service
        AddBeamFor(&UserDetailsServiceConfiguration{})
        GetContainer().EnableScanning()
    })
    
    It("should allow admin to access protected routes", func() {
        // ... Add any test-specific mock Beams here ...
        
        // Initialize the test container
        err := GetContainer().Initialize()
        
        // Ensure initialization occurred without error
        Expect(err).NotTo(HaveOccurred())
        
        // ... test logic ...
    })
})
```
