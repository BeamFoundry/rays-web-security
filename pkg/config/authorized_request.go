package config

import (
	. "github.com/BeamFoundry/rays/pkg/lang"
	. "github.com/BeamFoundry/rays/pkg/util"
	. "github.com/BeamFoundry/rays/pkg/web"
)

// AuthorizedHttpRequest is an object combining a [HttpMatcher] and a [HttpPolicy].
//
// An [AuthorizedHttpRequest] is constructed from an [AuthorizedHttpRequestConfigurer] which
type AuthorizedHttpRequest struct {
	httpMatcher *HttpMatcher
	httpPolicy  *HttpPolicy
}

// Matcher() returns the configured [HttpMatcher]
func (this *AuthorizedHttpRequest) Matcher() *HttpMatcher {
	return this.httpMatcher
}

// Policy() returns the configured [httpPolicy]
func (this *AuthorizedHttpRequest) Policy() *HttpPolicy {
	return this.httpPolicy
}

// AuthorizedHttpRequestConfigurer is a builder for [AuthorizedHttpRequest] used by [HttpSecurityBuilder].
type AuthorizedHttpRequestConfigurer struct {
	next *HttpSecurityBuilder
}

func (this *AuthorizedHttpRequestConfigurer) setHttpMatcher(httpMatcher *HttpMatcher) {
	this.next.httpSecurity.authorizedRequests = append(this.next.httpSecurity.authorizedRequests, &AuthorizedHttpRequest{})
	authorized := this.next.httpSecurity.authorizedRequests
	authorized[len(authorized)-1].httpMatcher = httpMatcher
}

func (this *AuthorizedHttpRequestConfigurer) policySelector() *HttpPolicyConfigurer[*AuthorizedHttpRequestConfigurer] {
	return HttpPolicyConfigurer[*AuthorizedHttpRequestConfigurer]{}.newConfigurer(
		this,
		func(httpPolicy *HttpPolicy) {
			authorized := this.next.httpSecurity.authorizedRequests
			authorized[len(authorized)-1].httpPolicy = httpPolicy
		},
	)
}

func (this *AuthorizedHttpRequestConfigurer) matchPaths(path string, paths []string) []*AntMatcher {
	matchers := []*AntMatcher{}

	if matcher, err := (AntMatcher{}).New(path); err == nil {
		matchers = append(matchers, matcher)
	}
	for _, path := range paths {
		if matcher, err := (AntMatcher{}).New(path); err == nil {
			matchers = append(matchers, matcher)
		}
	}
	return matchers
}

// Paths() add a matching rule for the provided paths.
func (this *AuthorizedHttpRequestConfigurer) Paths(path string, paths ...string) *HttpPolicyConfigurer[*AuthorizedHttpRequestConfigurer] {
	this.setHttpMatcher(&HttpMatcher{matcher: Enum[HttpMatcherEnum]{}.New().PATHS, paths: this.matchPaths(path, paths)})
	return this.policySelector()
}

// Method() add a matchig rule for this particular HttpMethod.
func (this *AuthorizedHttpRequestConfigurer) Method(method HttpMethod) *HttpPolicyConfigurer[*AuthorizedHttpRequestConfigurer] {
	this.setHttpMatcher(&HttpMatcher{matcher: Enum[HttpMatcherEnum]{}.New().METHOD, method: method})
	return this.policySelector()
}

// MethodAndPaths() add a matching rule for this particular HttpMethod and the provided paths.
func (this *AuthorizedHttpRequestConfigurer) MethodAndPaths(method HttpMethod, path string, paths ...string) *HttpPolicyConfigurer[*AuthorizedHttpRequestConfigurer] {
	this.setHttpMatcher(&HttpMatcher{matcher: Enum[HttpMatcherEnum]{}.New().METHOD_AND_PATHS, paths: this.matchPaths(path, paths), method: method})
	return this.policySelector()
}

// And() returns to HttpSecurityBuilder.
func (this *AuthorizedHttpRequestConfigurer) And() *HttpSecurityBuilder {
	return this.next
}
