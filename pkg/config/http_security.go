package config

import (
	"slices"

	. "github.com/BeamFoundry/rays/pkg/lang"
	. "github.com/BeamFoundry/rays/pkg/util"

	. "github.com/BeamFoundry/rays-web-security/pkg/core"
)

// HttpSecurity is the main object configuration to create in order to activate Web Security.
//
// It has to be created using [HttpSecurityBuilder], and be registered as a Beam through a
// [github.com/BeamFoundry/rays-web-security/pkg/core.Configuration].
//
// NOTE: More than one HttpSecurity object may be registered for the same [Server], with at most
// one without any path AntMatchers.
type HttpSecurity struct {
	rememberme         RememberMeService
	httpPolicy         *HttpPolicy
	csrf               *CsrfEnabler
	formLogin          *FormLogin
	filters            []SecurityFilter
	customFilterNames  []string
	securityFilters    map[string]any
	injectedFilters    map[string]SecurityFilter `@:"Inject"`
	authorizedRequests []*AuthorizedHttpRequest
	matchers           []*AntMatcher
	session            SessionCreationPolicy
	basic              bool
}

// PostConstruct() implements [BeamPostConstruct]
func (this *HttpSecurity) PostConstruct() Error {
	addFilter := func(filter SecurityFilter) {
		if slices.Contains(this.filters, filter) {
			return
		}
		this.filters = append(this.filters, filter)
	}

	for _, name := range this.customFilterNames {
		if filter, ok := this.injectedFilters[name]; ok {
			addFilter(filter)
		}
	}
	var remaining []string
	for name := range this.injectedFilters {
		if name != "basicAuthFilter" && name != "formLoginFilter" && !slices.Contains(this.customFilterNames, name) {
			remaining = append(remaining, name)
		}
	}
	slices.Sort(remaining)
	for _, name := range remaining {
		addFilter(this.injectedFilters[name])
	}
	if filter, ok := this.injectedFilters["basicAuthFilter"]; ok {
		addFilter(filter)
	}
	if filter, ok := this.injectedFilters["formLoginFilter"]; ok {
		addFilter(filter)
	}
	return nil
}

// AuthorizedHTTPRequests() returns a slice of configured AuthorizedHttpRequest.
func (this *HttpSecurity) AuthorizedHTTPRequests() []*AuthorizedHttpRequest {
	return this.authorizedRequests
}

// DefaultHTTPPolicy() return the default [HttpPolicy]
func (this *HttpSecurity) DefaultHTTPPolicy() *HttpPolicy {
	return this.httpPolicy
}

// Csrf() rerturns the [CsrfEnabler] object, if configured.
func (this *HttpSecurity) Csrf() *CsrfEnabler {
	return this.csrf
}

// Basic() returns whether BasicAuth has been activated.
func (this *HttpSecurity) Basic() bool {
	return this.basic
}

// FormLogin() return the [FormLogin] object, if configured.
func (this *HttpSecurity) FormLogin() *FormLogin {
	return this.formLogin
}

// SessionCreationPolicy() returns the SessionCreationPolicy configured.
func (this *HttpSecurity) SessionCreationPolicy() SessionCreationPolicy {
	return this.session
}

// Matchers() returns a slice of AntMatcher, corresponding
func (this *HttpSecurity) Matchers() []*AntMatcher {
	return this.matchers
}

// Filters() returns the configured [SecurityFilter].
//
// This includes first the ones configured via [HttpSecurityBuilder], and globol ones
// for FormLogin  or BasicAuth which will be included automatically.
func (this *HttpSecurity) Filters() []SecurityFilter {
	return this.filters
}

// SecurityFilters() returns the configured custom security filter configurations.
func (this *HttpSecurity) SecurityFilters() map[string]any {
	return this.securityFilters
}

// RememberMeService() returns an optionally configured [RememberMeService].
//
// WARNING: [RememberMeService] should always be first registered as beams,
// before being added in the [HttpSecurityBuilder].
func (this *HttpSecurity) RememberMeService() Optional[RememberMeService] {
	return OptionalOf(this.rememberme)
}

// HttpSecurityBuilder is a builder for [httpSecurity]
type HttpSecurityBuilder struct {
	httpSecurity HttpSecurity
}

// AuthorizedHTTPRequests() let you access the [AuthorizedHttpRequestConfigurer], to add rules of
// access authorization.
func (this *HttpSecurityBuilder) AuthorizedHTTPRequests() *AuthorizedHttpRequestConfigurer {
	return &AuthorizedHttpRequestConfigurer{this}
}

// AnyRequest() lets you configure the default [HttpPolicy] if no [AuthorizedHTTPRequests] match?
func (this *HttpSecurityBuilder) AnyRequest() *HttpPolicyConfigurer[*HttpSecurityBuilder] {
	return HttpPolicyConfigurer[*HttpSecurityBuilder]{}.newConfigurer(
		this,
		func(httpPolicy *HttpPolicy) {
			this.httpSecurity.httpPolicy = httpPolicy
		},
	)
}

// Basic() enabled BasicAuth.
//
// WARNING: This needs a [UserDetailsService] to be defined.
func (this *HttpSecurityBuilder) Basic() *HttpSecurityBuilder {
	this.httpSecurity.basic = true
	return this
}

// FormLogin() enable and lets you configure the FormLogin process.
//
// WARNING: This needs a [UserDetailsService] to be defined.
func (this *HttpSecurityBuilder) FormLogin() *FormLoginConfigurer {
	return FormLoginConfigurer{}.newConfigurer(this)
}

// AddCustomFilter() lets you add a custom [SecurityFilter] that will be evaluated by the [SecurityFilterChain].
// They will be evaluated before global ones like for BasicAuth or FormLogin.
//
// Deprecated: Use [HttpSecurityBuilder.AddCustomSecurityFilter] instead.
func (this *HttpSecurityBuilder) AddCustomFilter(filter SecurityFilter) *HttpSecurityBuilder {
	this.httpSecurity.filters = append(this.httpSecurity.filters, filter)
	return this
}

// AddCustomSecurityFilter() populates a map[string]any in its HttpSecurity of an id and an object struct pointer.
//
// This configuration can be retrieved via [HttpSecurity.SecurityFilters] by a prototype [SecurityFilter]
// implementation and its WithContext() function (implementing [BeamPostConstructWithContext]) to decide if
// that HttpSecurity requires that filter (if the map contains the key and an object pointer of that type).
func (this *HttpSecurityBuilder) AddCustomSecurityFilter(name string, obj any) *HttpSecurityBuilder {
	if this.httpSecurity.securityFilters == nil {
		this.httpSecurity.securityFilters = make(map[string]any)
	}
	if _, ok := this.httpSecurity.securityFilters[name]; !ok {
		this.httpSecurity.customFilterNames = append(this.httpSecurity.customFilterNames, name)
	}
	this.httpSecurity.securityFilters[name] = obj
	return this
}

// WARNING: [RememberMeService] should always be first registered as beams,
// before being added in the [HttpSecurityBuilder].
func (this *HttpSecurityBuilder) RememberMe(rememberme RememberMeService) *HttpSecurityBuilder {
	this.httpSecurity.rememberme = rememberme
	return this
}

// Csrf() lets yoy disable the CSRF.
func (this *HttpSecurityBuilder) Csrf() *CsrfConfigurer {
	return CsrfConfigurer{}.newConfigurer(this)
}

// SessionCreationPolicy() lets you change the Session creation policy.
func (this *HttpSecurityBuilder) SessionCreationPolicy() *SessionCreationPolicyConfigurer {
	return SessionCreationPolicyConfigurer{}.newConfigurer(this)
}

// Match() lets you restrict this [HttpSecurity] to certains paths.
//
// NOTE: More than one HttpSecurity object may be registered for the same [Server], with at most
// one without any path AntMatchers.
func (this *HttpSecurityBuilder) Match(path string, paths ...string) *HttpSecurityBuilder {
	addMatcher := func(path string) {
		if matcher, err := (AntMatcher{}.New(path)); err == nil {
			this.httpSecurity.matchers = append(this.httpSecurity.matchers, matcher)
		}
	}
	addMatcher(path)
	for _, path := range paths {
		addMatcher(path)
	}
	return this
}

// Build() builds and return a new httpSecurity.
func (this *HttpSecurityBuilder) Build() *HttpSecurity {
	if this.httpSecurity.csrf == nil {
		this.httpSecurity.csrf = &CsrfEnabler{}
	}
	if this.httpSecurity.httpPolicy == nil {
		this.httpSecurity.httpPolicy = HttpPolicy{}.newPolicy(Enum[HttpPolicyEnum]{}.New().PERMIT_ALL, []string{})
	}
	if this.httpSecurity.securityFilters == nil {
		this.httpSecurity.securityFilters = make(map[string]any)
	}

	return &this.httpSecurity
}
