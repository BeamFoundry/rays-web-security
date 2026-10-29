package auth_test

import (
	. "github.com/BeamFoundry/rays-web-security/pkg/auth"
	. "github.com/BeamFoundry/rays-web-security/pkg/core"
	. "github.com/BeamFoundry/rays-web-security/pkg/testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("PreAuthenticatedAuthenticationToken", func() {
	It("can be used unauthenticated", func() {
		token := PreAuthenticatedAuthenticationToken{}.New("testuser", "testcredentials")
		Expect(token.IsAuthenticated()).To(BeFalse())
		Expect(token.GetPrincipal()).To(Equal("testuser"))
		Expect(token.GetCredentials()).To(Equal("testcredentials"))
		Expect(token.GetName()).NotTo(BeEmpty())
	})

	It("can be used authenticated", func() {
		authorities := []GrantedAuthority{Authority("ROLE_USER"), Authority("ROLE_ADMIN")}
		token := PreAuthenticatedAuthenticationToken{}.NewAuthenticated("testuser", "testcredentials", authorities)
		Expect(token.IsAuthenticated()).To(BeTrue())
		Expect(token.GetPrincipal()).To(Equal("testuser"))
		Expect(token.GetCredentials()).To(Equal("testcredentials"))
		Expect(token.GetAuthorities()).To(Equal(authorities))

		token.EraseCredentials()
		Expect(token.GetCredentials()).To(BeNil())
	})
})

var _ = Describe("UserDetailsByNameServiceWrapper", func() {
	It("loads user details by username string", func() {
		manager := InMemoryUserDetailsManager{}.New(DefaultPasswordEncoder)
		_ = manager.NewUser().
			WithUsername("john").
			WithPassword("secret").
			WithAuthorities([]GrantedAuthority{Authority("ROLE_ADMIN")}).Build()

		wrapper := UserDetailsByNameServiceWrapper{}.New(manager)
		token := PreAuthenticatedAuthenticationToken{}.New("john", "")

		details, err := wrapper.LoadUserDetails(token)
		Expect(err).NotTo(HaveOccurred())
		Expect(details.GetUsername()).To(Equal("john"))
		Expect(details.GetAuthorities()).To(Equal([]GrantedAuthority{Authority("ROLE_ADMIN")}))
	})

	It("loads user details when principal is already UserDetails", func() {
		manager := InMemoryUserDetailsManager{}.New(DefaultPasswordEncoder)
		user := manager.NewUser().
			WithUsername("existing").
			WithPassword("secret").
			WithAuthorities([]GrantedAuthority{Authority("ROLE_USER")}).Build()

		wrapper := UserDetailsByNameServiceWrapper{}.New(manager)
		token := PreAuthenticatedAuthenticationToken{}.New(user, "")

		details, err := wrapper.LoadUserDetails(token)
		Expect(err).NotTo(HaveOccurred())
		Expect(details.GetUsername()).To(Equal("existing"))
	})

	It("returns error if user not found", func() {
		manager := InMemoryUserDetailsManager{}.New(DefaultPasswordEncoder)
		wrapper := UserDetailsByNameServiceWrapper{}.New(manager)
		token := PreAuthenticatedAuthenticationToken{}.New("unknown", "")

		details, err := wrapper.LoadUserDetails(token)
		Expect(err).To(HaveOccurred())
		Expect(details).To(BeNil())
	})
})

var _ = Describe("PreAuthenticatedGrantedAuthoritiesUserDetailsService", func() {
	It("builds UserDetails from token authorities without database lookup", func() {
		service := PreAuthenticatedGrantedAuthoritiesUserDetailsService{}.New()
		token := PreAuthenticatedAuthenticationToken{}.New("proxyuser", "")
		token.Authorities = []GrantedAuthority{Authority("ROLE_USER"), Authority("ROLE_API")}

		details, err := service.LoadUserDetails(token)
		Expect(err).NotTo(HaveOccurred())
		Expect(details.GetUsername()).To(Equal("proxyuser"))
		Expect(details.GetPassword()).To(BeEmpty())
		Expect(details.GetAuthorities()).To(Equal([]GrantedAuthority{Authority("ROLE_USER"), Authority("ROLE_API")}))
		Expect(details.IsExpired()).To(BeFalse())
		Expect(details.IsCredentialExpired()).To(BeFalse())
		Expect(details.IsDisabled()).To(BeFalse())
		Expect(details.IsLocked()).To(BeFalse())
	})

	It("returns existing UserDetails if principal is already UserDetails", func() {
		manager := InMemoryUserDetailsManager{}.New(DefaultPasswordEncoder)
		user := manager.NewUser().
			WithUsername("alice").
			WithPassword("").
			WithAuthorities([]GrantedAuthority{Authority("ROLE_USER")}).Build()

		service := PreAuthenticatedGrantedAuthoritiesUserDetailsService{}.New()
		token := PreAuthenticatedAuthenticationToken{}.New(user, "")

		details, err := service.LoadUserDetails(token)
		Expect(err).NotTo(HaveOccurred())
		Expect(details.GetUsername()).To(Equal("alice"))
	})
})
