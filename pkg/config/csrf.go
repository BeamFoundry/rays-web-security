package config

// CsrfEnabler is an object noting if CSRF should be disabled.
type CsrfEnabler struct {
	disabled bool
}

func (this *CsrfEnabler) Disabled() bool {
	return this.disabled
}

// CsrfConfigurer is an object used to disable CSRF.
type CsrfConfigurer struct {
	next *HttpSecurityBuilder
	csrf CsrfEnabler
}

func (this CsrfConfigurer) newConfigurer(httpSecurityBuilder *HttpSecurityBuilder) *CsrfConfigurer {
	this.next = httpSecurityBuilder
	return &this
}

// Disable() will disable the CSRF and return to HttpSecurityBuilder
func (this *CsrfConfigurer) Disable() *HttpSecurityBuilder {
	this.csrf.disabled = true
	this.next.httpSecurity.csrf = &this.csrf
	return this.next
}
