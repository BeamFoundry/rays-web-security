package config

import (
	. "github.com/BeamFoundry/rays-web-security/pkg/core"
)

// SetInjectedFiltersForTest allows test suites to inject filters directly for PostConstruct testing.
func (this *HttpSecurity) SetInjectedFiltersForTest(filters map[string]SecurityFilter) {
	this.injectedFilters = filters
}

// SetTrustedProxiesForTest allows test suites to set trusted proxies directly, including empty entries.
func (this *PreAuth) SetTrustedProxiesForTest(proxies []string) {
	this.trustedProxies = proxies
}
