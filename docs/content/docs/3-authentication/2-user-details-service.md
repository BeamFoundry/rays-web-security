---
title: "UserDetailsService"
weight: 2
---

# 2. Implementing `UserDetailsService`

Next, create a Service that implements `UserDetailsService`. The framework will automatically detect this Beam and use it during the login process.

If the user cannot be found, you simply return `nil`, and the framework will handle the failed authentication safely.

```go
package security

import (
    . "github.com/BeamFoundry/rays-web-security/pkg/core"
    . "github.com/BeamFoundry/rays/pkg/core"
    . "github.com/BeamFoundry/rays/pkg/lang"
)

type DomainUserDetailsService struct {
    Service
    userRepo *UserRepository `@:"Inject"`
}

func (s *DomainUserDetailsService) LoadUserByUsername(username string) UserDetails {
    userOpt := s.userRepo.FindByEmail(username)

    // Return the user if found
    if user, ok := userOpt.Get(); ok {
        return user
    }

    // Return nil if the user does not exist
    return nil
}

```
