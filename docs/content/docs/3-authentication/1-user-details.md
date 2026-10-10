---
title: "UserDetails Interface"
weight: 1
---

# 1. The `UserDetails` Interface

First, adapt your domain model to fulfill the framework's `UserDetails` interface, located in `pkg/core`. 

Note that the framework provides a convenient `Authority` string alias to easily generate `GrantedAuthority` slice elements.

```go
package models

import . "github.com/BeamFoundry/rays-web-security/pkg/core"

type User struct {
    ID           uint
    Email        string
    PasswordHash string
    Role         string
}

// Implement the UserDetails interface
func (u *User) GetUsername() string { return u.Email }
func (u *User) GetPassword() string { return u.PasswordHash }
func (u *User) GetAuthorities() []GrantedAuthority {
    return []GrantedAuthority{ Authority("ROLE_" + u.Role) }
}

// These return false when the account is active and unrestricted
func (u *User) IsExpired() bool           { return false }
func (u *User) IsCredentialExpired() bool { return false }
func (u *User) IsDisabled() bool          { return false }
func (u *User) IsLocked() bool            { return false }
```
