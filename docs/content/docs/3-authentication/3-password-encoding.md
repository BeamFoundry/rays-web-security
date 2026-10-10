---
title: "Password Encoding"
weight: 3
---

# 3. Password Encoding

Never store plain-text passwords. When you boot the application, `internal/autoconfig` automatically registers a highly secure, upgradeable default `PasswordEncoder`.

## The Delegating Password Encoder

To support seamless algorithm migrations over time (a best practice from Spring Security), the default encoder is a `DelegatingPasswordEncoder`.

It automatically wraps a `BCryptPasswordEncoder` (with a cost of 10) mapped to the "bcrypt" prefix. This means your hashed passwords will automatically be formatted with a prefix, looking something like this:
`{bcrypt}$2a$10$wN1FzZ2...`

## Overriding the Default Encoder

If you need to override this default (for example, to increase the hashing cost to 12 or to add support for legacy passwords), you can simply define your own `PasswordEncoder` Beam:

```go
package security

import (
    . "github.com/BeamFoundry/rays-web-security/pkg/core"
    . "github.com/BeamFoundry/rays-web-security/pkg/password"
    . "github.com/BeamFoundry/rays/pkg/core"
)

type PasswordConfig struct {
    Configuration
}

// Overrides the auto-configured DelegatingPasswordEncoder
func (this *PasswordConfig) PasswordEncoder() PasswordEncoder {
    return DelegatingPasswordEncoder{}.New(
        "bcrypt",
        map[string]PasswordEncoder{
            "bcrypt": BCryptPasswordEncoder{}.New(12), // Increased cost!
            "noop":   NoOpPasswordEncoder{}.New(),     // Support legacy plaintext (Not Recommended!)
        },
    )
}

```
