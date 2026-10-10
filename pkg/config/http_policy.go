package config

import (
	"fmt"
	"reflect"
	"slices"

	. "github.com/BeamFoundry/rays/pkg/lang"

	. "github.com/BeamFoundry/rays-web-security/pkg/auth"
	. "github.com/BeamFoundry/rays-web-security/pkg/core"
)

type HttpPolicyEnum struct {
	PERMIT_ALL,
	DENY_ALL,
	HAS_AUTHORITY,
	HAS_ANY_AUTHORITY,
	ANONYMOUS,
	AUTHENTICATED Enum[HttpPolicyEnum]
}

type HttpPolicy struct {
	authorities []string
	policy      Enum[HttpPolicyEnum]
}

func (this HttpPolicy) newPolicy(policy Enum[HttpPolicyEnum], authorities []string) *HttpPolicy {
	this.policy = policy
	this.authorities = authorities
	return &this
}

func (this *HttpPolicy) Allow(authentication Authentication) bool {
	switch this.policy {
	case Enum[HttpPolicyEnum]{}.New().PERMIT_ALL:
		return true
	case Enum[HttpPolicyEnum]{}.New().DENY_ALL:
		return false
	case Enum[HttpPolicyEnum]{}.New().HAS_AUTHORITY, Enum[HttpPolicyEnum]{}.New().HAS_ANY_AUTHORITY:
		for _, authority := range authentication.GetAuthorities() {
			if slices.Contains(this.authorities, authority.Authority()) {
				return true
			}
		}
	case Enum[HttpPolicyEnum]{}.New().ANONYMOUS:
		if reflect.TypeOf(authentication) == reflect.TypeFor[*AnonymousAuthenticationToken]() {
			return true
		}
	case Enum[HttpPolicyEnum]{}.New().AUTHENTICATED:
		return authentication.IsAuthenticated()
	default:
	}
	return false
}

func (this *HttpPolicy) String() string {
	switch this.policy {
	case Enum[HttpPolicyEnum]{}.New().HAS_AUTHORITY, Enum[HttpPolicyEnum]{}.New().HAS_ANY_AUTHORITY:
		return fmt.Sprintf("%s%s", this.policy, this.authorities)
	default:
		return this.policy.String()
	}
}

// HttpPolicyConfigurer is a generic type used to set the HttpPolicy on another object of type S.
type HttpPolicyConfigurer[S any] struct {
	next   S
	setter func(*HttpPolicy)
}

func (this HttpPolicyConfigurer[S]) newConfigurer(next S, setter func(*HttpPolicy)) *HttpPolicyConfigurer[S] {
	this.next = next
	this.setter = setter
	return &this
}

// PermitAll() configure the HttpPolicy to permit all access.
func (this *HttpPolicyConfigurer[S]) PermitAll() S {
	this.setter(HttpPolicy{}.newPolicy(Enum[HttpPolicyEnum]{}.New().PERMIT_ALL, []string{}))
	return this.next
}

// DenyAll() configure the HttpPolicy to deny all access.
func (this *HttpPolicyConfigurer[S]) DenyAll() S {
	this.setter(HttpPolicy{}.newPolicy(Enum[HttpPolicyEnum]{}.New().DENY_ALL, []string{}))
	return this.next
}

// HasAuthority() configure the HttpPolicy to permit access only to te provided authority.
//
// An authority is for example "ROLE_USER".
func (this *HttpPolicyConfigurer[S]) HasAuthority(authority string) S {
	this.setter(HttpPolicy{}.newPolicy(Enum[HttpPolicyEnum]{}.New().HAS_AUTHORITY, []string{authority}))
	return this.next
}

// HasRole() configure the HttpPolicy to permit access only to the provided role.
//
// WARNING: A role is for example "USER". Internally it will be converted to an authority of "ROLE_USER".
func (this *HttpPolicyConfigurer[S]) HasRole(role string) S {
	this.setter(HttpPolicy{}.newPolicy(Enum[HttpPolicyEnum]{}.New().HAS_AUTHORITY, []string{"ROLE_" + role}))
	return this.next
}

// HasAnyAuthority() configure the HttpPolicy to permit access only to the provided authorities.
//
// NOTE: An authority is for example "ROLE_USER".
func (this *HttpPolicyConfigurer[S]) HasAnyAuthority(authorities []string) S {
	this.setter(HttpPolicy{}.newPolicy(Enum[HttpPolicyEnum]{}.New().HAS_ANY_AUTHORITY, authorities))
	return this.next
}

// HasAnyRole() configure the HttpPolicy to permit access only to the provided roles.
//
// WARNING: A role is for example "USER". Internally it will be converted to an authority of "ROLE_USER".
func (this *HttpPolicyConfigurer[S]) HasAnyRole(roles []string) S {
	var authorities []string
	for _, role := range roles {
		authorities = append(authorities, "ROLE_"+role)
	}
	this.setter(HttpPolicy{}.newPolicy(Enum[HttpPolicyEnum]{}.New().HAS_ANY_AUTHORITY, authorities))
	return this.next
}

// Anonymous() configure the HttpPolicy to permit access only to anonymous users.
func (this *HttpPolicyConfigurer[S]) Anonymous() S {
	this.setter(HttpPolicy{}.newPolicy(Enum[HttpPolicyEnum]{}.New().ANONYMOUS, []string{}))
	return this.next
}

// Authenticated() configure the HttpPolicy to permit access only to authenticated users.
func (this *HttpPolicyConfigurer[S]) Authenticated() S {
	this.setter(HttpPolicy{}.newPolicy(Enum[HttpPolicyEnum]{}.New().AUTHENTICATED, []string{}))
	return this.next
}
