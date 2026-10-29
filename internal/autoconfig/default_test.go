package autoconfig

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	. "github.com/BeamFoundry/rays/pkg/core"
	. "github.com/BeamFoundry/rays/pkg/lang"

	. "github.com/BeamFoundry/rays-web-security/pkg/auth"
	. "github.com/BeamFoundry/rays-web-security/pkg/core"
	. "github.com/BeamFoundry/rays-web-security/pkg/password"
	. "github.com/BeamFoundry/rays-web-security/pkg/testing"
)

func TestAutoconfig(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Internal/Autoconfig Suite")
}

var _ = Describe("DefaultConfiguration", func() {
	It("provides default PasswordEncoder", func() {
		cfg := &DefaultConfiguration{}
		encoder := cfg.PasswordEncoder(struct{ ConditionalOnMissingBeam }{})
		Expect(encoder).NotTo(BeNil())
	})

	It("provides UserDetailsAuthenticationProvider when service is present or nil when absent", func() {
		cfg := &DefaultConfiguration{}
		encoder := NoOpPasswordEncoder{}.New()

		// Absent
		pNil := cfg.UserDetailsAuthenticationProvider(struct {
			ConditionalOnMissingBeam
			encoder PasswordEncoder              `@:"Inject"`
			service Optional[UserDetailsService] `@:"Inject"`
		}{
			encoder: encoder,
			service: OptionalEmpty[UserDetailsService](),
		})
		Expect(pNil).To(BeNil())

		// Present
		uds := InMemoryUserDetailsManager{}.New(encoder)
		p := cfg.UserDetailsAuthenticationProvider(struct {
			ConditionalOnMissingBeam
			encoder PasswordEncoder              `@:"Inject"`
			service Optional[UserDetailsService] `@:"Inject"`
		}{
			encoder: encoder,
			service: OptionalOf[UserDetailsService](uds),
		})
		Expect(p).NotTo(BeNil())
	})

	It("provides AuthenticationUserDetailsService wrapping UserDetailsService or defaulting", func() {
		cfg := &DefaultConfiguration{}

		// Default (no UserDetailsService)
		sDefault := cfg.AuthenticationUserDetailsService(struct {
			ConditionalOnMissingBeam
			userDetailsService Optional[UserDetailsService] `@:"Inject"`
		}{
			userDetailsService: OptionalEmpty[UserDetailsService](),
		})
		Expect(sDefault).NotTo(BeNil())

		// Wrapped UserDetailsService
		encoder := NoOpPasswordEncoder{}.New()
		uds := InMemoryUserDetailsManager{}.New(encoder)
		sWrapped := cfg.AuthenticationUserDetailsService(struct {
			ConditionalOnMissingBeam
			userDetailsService Optional[UserDetailsService] `@:"Inject"`
		}{
			userDetailsService: OptionalOf[UserDetailsService](uds),
		})
		Expect(sWrapped).NotTo(BeNil())
	})

	It("provides PreAuthenticatedAuthenticationProvider when service is present or nil when absent", func() {
		cfg := &DefaultConfiguration{}

		// Absent
		pNil := cfg.PreAuthenticatedAuthenticationProvider(struct {
			ConditionalOnMissingBeam
			service Optional[AuthenticationUserDetailsService] `@:"Inject"`
		}{
			service: OptionalEmpty[AuthenticationUserDetailsService](),
		})
		Expect(pNil).To(BeNil())

		// Present
		service := PreAuthenticatedGrantedAuthoritiesUserDetailsService{}.New()
		p := cfg.PreAuthenticatedAuthenticationProvider(struct {
			ConditionalOnMissingBeam
			service Optional[AuthenticationUserDetailsService] `@:"Inject"`
		}{
			service: OptionalOf[AuthenticationUserDetailsService](service),
		})
		Expect(p).NotTo(BeNil())
	})
})
