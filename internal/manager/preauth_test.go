package manager_test

import (
	. "github.com/BeamFoundry/rays-web-security/internal/manager"
	. "github.com/BeamFoundry/rays-web-security/pkg/auth"
	. "github.com/BeamFoundry/rays-web-security/pkg/core"
	. "github.com/BeamFoundry/rays-web-security/pkg/password"
	. "github.com/BeamFoundry/rays-web-security/pkg/testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

type mockFailingPreAuthUserService struct {
	err       AuthenticationException
	returnNil bool
}

//nolint:nilnil // testing nil user handling
func (m *mockFailingPreAuthUserService) LoadUserDetails(_ Authentication) (UserDetails, AuthenticationException) {
	if m.returnNil {
		return nil, nil
	}
	return nil, m.err
}

var _ = Describe("PreAuthenticatedAuthenticationProvider", func() {
	It("authenticates a valid pre-authenticated token and copies token authorities if user has none", func() {
		service := PreAuthenticatedGrantedAuthoritiesUserDetailsService{}.New()
		provider := PreAuthenticatedAuthenticationProvider{}.New(service)

		token := PreAuthenticatedAuthenticationToken{}.New("alice", "cert")
		token.Authorities = []GrantedAuthority{Authority("ROLE_ADMIN")}

		Expect(provider.Supports(token)).To(BeTrue())
		Expect(provider.Supports(UsernamePasswordAuthenticationToken{}.New("a", "b"))).To(BeFalse())

		auth, err := provider.Authenticate(token)
		Expect(err).NotTo(HaveOccurred())
		Expect(auth.IsAuthenticated()).To(BeTrue())
		Expect(auth.GetPrincipal()).NotTo(BeNil())
		Expect(auth.GetCredentials()).To(BeNil())
		Expect(token.GetCredentials()).To(BeNil())
		Expect(auth.GetAuthorities()).To(Equal([]GrantedAuthority{Authority("ROLE_ADMIN")}))
	})

	It("preserves user authorities when user details already has authorities", func() {
		manager := InMemoryUserDetailsManager{}.New(NoOpPasswordEncoder{}.New())
		_ = manager.NewUser().
			WithUsername("bob").
			WithPassword("secret").
			WithAuthorities([]GrantedAuthority{Authority("ROLE_USER")}).
			Build()

		wrapper := UserDetailsByNameServiceWrapper{}.New(manager)
		provider := PreAuthenticatedAuthenticationProvider{}.New(wrapper)

		token := PreAuthenticatedAuthenticationToken{}.New("bob", "cert")
		token.Authorities = []GrantedAuthority{Authority("ROLE_EXTERNAL")}

		auth, err := provider.Authenticate(token)
		Expect(err).NotTo(HaveOccurred())
		Expect(auth.GetAuthorities()).To(Equal([]GrantedAuthority{Authority("ROLE_USER")}))
	})

	It("copies token authorities when user details has no authorities", func() {
		manager := InMemoryUserDetailsManager{}.New(NoOpPasswordEncoder{}.New())
		_ = manager.NewUser().
			WithUsername("bob").
			WithPassword("secret").
			Build() // No authorities assigned to user

		wrapper := UserDetailsByNameServiceWrapper{}.New(manager)
		provider := PreAuthenticatedAuthenticationProvider{}.New(wrapper)

		token := PreAuthenticatedAuthenticationToken{}.New("bob", "cert")
		token.Authorities = []GrantedAuthority{Authority("ROLE_EXTERNAL")}

		auth, err := provider.Authenticate(token)
		Expect(err).NotTo(HaveOccurred())
		Expect(auth.GetAuthorities()).To(Equal([]GrantedAuthority{Authority("ROLE_EXTERNAL")}))
	})

	It("rejects token with missing principal or unsupported token type", func() {
		service := PreAuthenticatedGrantedAuthoritiesUserDetailsService{}.New()
		provider := PreAuthenticatedAuthenticationProvider{}.New(service)

		token := PreAuthenticatedAuthenticationToken{}.New("", "")
		_, err := provider.Authenticate(token)
		Expect(err).To(HaveOccurred())

		tokenNil := PreAuthenticatedAuthenticationToken{}.New(nil, "")
		_, err = provider.Authenticate(tokenNil)
		Expect(err).To(HaveOccurred())

		unsupported := UsernamePasswordAuthenticationToken{}.New("user", "pass")
		_, err = provider.Authenticate(unsupported)
		Expect(err).To(HaveOccurred())
	})

	It("fails when service is invalid", func() {
		provider := PreAuthenticatedAuthenticationProvider{}
		token := PreAuthenticatedAuthenticationToken{}.New("alice", "")
		_, err := provider.Authenticate(token)
		Expect(err).To(HaveOccurred())
	})

	It("propagates load error from service", func() {
		mockErr := BadCredentialsException{}.New("custom load error", nil)
		provider := PreAuthenticatedAuthenticationProvider{}.New(&mockFailingPreAuthUserService{err: mockErr})
		token := PreAuthenticatedAuthenticationToken{}.New("alice", "")
		_, err := provider.Authenticate(token)
		Expect(err).To(Equal(mockErr))
	})

	It("fails when service returns nil UserDetails", func() {
		provider := PreAuthenticatedAuthenticationProvider{}.New(&mockFailingPreAuthUserService{returnNil: true})
		token := PreAuthenticatedAuthenticationToken{}.New("alice", "")
		_, err := provider.Authenticate(token)
		Expect(err).To(HaveOccurred())
	})

	It("checks account status flags and raises appropriate exceptions", func() {
		testAccountStatus := func(modify func(b *UserBuilder[*InMemoryUserDetailsManager])) {
			manager := InMemoryUserDetailsManager{}.New(NoOpPasswordEncoder{}.New())
			builder := manager.NewUser().
				WithUsername("statususer").
				WithPassword("secret").
				WithAuthorities([]GrantedAuthority{Authority("ROLE_USER")})
			modify(builder)
			_ = builder.Build()

			wrapper := UserDetailsByNameServiceWrapper{}.New(manager)
			provider := PreAuthenticatedAuthenticationProvider{}.New(wrapper)
			token := PreAuthenticatedAuthenticationToken{}.New("statususer", "")

			_, err := provider.Authenticate(token)
			Expect(err).To(HaveOccurred())
		}

		testAccountStatus(func(b *UserBuilder[*InMemoryUserDetailsManager]) { b.SetAccountExpired(true) })
		testAccountStatus(func(b *UserBuilder[*InMemoryUserDetailsManager]) { b.SetCredentialsExpired(true) })
		testAccountStatus(func(b *UserBuilder[*InMemoryUserDetailsManager]) { b.SetLocked(true) })
		testAccountStatus(func(b *UserBuilder[*InMemoryUserDetailsManager]) { b.SetDisabled(true) })
	})
})
