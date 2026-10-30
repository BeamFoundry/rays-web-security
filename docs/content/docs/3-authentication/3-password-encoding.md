---
title: "Password Encoding"
weight: 3
---

# 3. Password Encoding

Never store plain-text passwords. When you boot the application, `internal/autoconfig` automatically registers a highly secure, upgradeable default `PasswordEncoder`.

## The Delegating Password Encoder

To support seamless algorithm migrations over time (a best practice from Spring Security), the default encoder is a `DelegatingPasswordEncoder` (instantiated via `DelegatingPasswordEncoder{}.NewDefault()`).

By default, new passwords are encoded with `bcrypt` (using `BCryptDefaultCost = 10`), producing prefixed hashes such as:
`{bcrypt}$2a$10$wN1FzZ2...`

However, the default `DelegatingPasswordEncoder` natively supports verifying passwords encoded with any of the following standard algorithms:

| Identifier | Encoder | Implementation | Output Format / Standard |
| :--- | :--- | :--- | :--- |
| `bcrypt` | `BCryptPasswordEncoder` | `golang.org/x/crypto/bcrypt` | Blowfish crypt (`$2a$...`), default cost `10` (`BCryptDefaultCost`) |
| `argon2` | `Argon2PasswordEncoder` | `golang.org/x/crypto/argon2` | Standard Argon2id PHC string format (`$argon2id$v=19$m=16384,t=2,p=1$...`) |
| `pbkdf2` | `Pbkdf2PasswordEncoder` | `golang.org/x/crypto/pbkdf2` | Hex string `hex(salt \|\| hash)` with HMAC-SHA256, 310,000 iterations |
| `scrypt` | `SCryptPasswordEncoder` | `golang.org/x/crypto/scrypt` | Spring Security format `$<params_hex>$<salt_b64>$<hash_b64>` ($N=65536, r=8, p=1$) |
| `noop` | `NoOpPasswordEncoder` | Plaintext comparison | For legacy / test purposes only |

When verifying an incoming password against a stored hash starting with `{id}hash`, the `DelegatingPasswordEncoder` inspects the `{id}` prefix and delegates matching to the matching encoder.

## Available PasswordEncoders

All implementations reside in `github.com/BeamFoundry/rays-web-security/pkg/password`:

### `BCryptPasswordEncoder`
- **Default Constructor**: `BCryptPasswordEncoder{}.NewDefault()` (uses `BCryptDefaultCost = 10`)
- **Custom Constructor**: `BCryptPasswordEncoder{}.New(strength int)` (cost between `4` and `31`)

### `Argon2PasswordEncoder`
- **Default Constructor**: `Argon2PasswordEncoder{}.NewDefault()` (Argon2id, iterations: 2, memory: 16384 KiB, parallelism: 1, key length: 32, salt length: 16)
- **Custom Constructor**: `Argon2PasswordEncoder{}.New(iterations, memory uint32, parallelism uint8, keyLength uint32, saltLength int)`

### `Pbkdf2PasswordEncoder`
- **Default Constructor**: `Pbkdf2PasswordEncoder{}.NewDefault()` (HMAC-SHA256, iterations: 310,000, key length: 32, salt length: 16)
- **Custom Constructor**: `Pbkdf2PasswordEncoder{}.New(secret string, saltLength, iterations, keyLength int, algorithm string)`
- **Base64 Mode**: `.SetEncodeHashAsBase64(true)`

### `SCryptPasswordEncoder`
- **Default Constructor**: `SCryptPasswordEncoder{}.NewDefault()` (cpuCost: 65536, memoryCost: 8, parallelism: 1, key length: 32, saltLength: 16)
- **Custom Constructor**: `SCryptPasswordEncoder{}.New(cpuCost, memoryCost, parallelism, keyLength, saltLength int)`

### `NoOpPasswordEncoder`
- **Constructor**: `NoOpPasswordEncoder{}.New()` (plain-text matching, not secure for production)

## Overriding the Default Encoder

If you need to override this default (for example, to make `argon2` your default encoding algorithm or customize costs), you can define your own `PasswordEncoder` Beam in a Configuration class:

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
        "argon2", // Default to Argon2 for newly encoded passwords!
        map[string]PasswordEncoder{
            "argon2": Argon2PasswordEncoder{}.NewDefault(),
            "bcrypt": BCryptPasswordEncoder{}.New(12), // Custom cost
            "pbkdf2": Pbkdf2PasswordEncoder{}.NewDefault(),
            "scrypt": SCryptPasswordEncoder{}.NewDefault(),
            "noop":   NoOpPasswordEncoder{}.New(),
        },
    )
}
```
