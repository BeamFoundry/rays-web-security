package auth_test

import (
	"testing"

	_ "github.com/BeamFoundry/rays-web-security/internal/autoconfig"

	. "github.com/BeamFoundry/rays-web-security/pkg/auth"
	. "github.com/BeamFoundry/rays-web-security/pkg/core"
	. "github.com/BeamFoundry/rays-web-security/pkg/password"
	. "github.com/BeamFoundry/rays-web-security/pkg/testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestAuth(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Auth Suite")
}

var DefaultPasswordEncoder PasswordEncoder = DelegatingPasswordEncoder{}.New(
	"bcrypt", map[string]PasswordEncoder{"bcrypt": BCryptPasswordEncoder{}.New(10)},
)

var _ = Describe("UsernamePasswordAuthenticationToken", func() {
	It("can be used unanthenticated", func() {
		auth := UsernamePasswordAuthenticationToken{}.New("user", "user")
		Expect(auth.IsAuthenticated()).To(BeFalse())
		Expect(auth.GetName()).NotTo(BeEmpty())
	})

	It("can be used anthenticated", func() {
		userDetailsService := InMemoryUserDetailsManager{}.New(DefaultPasswordEncoder)
		user := userDetailsService.NewUser().
			WithUsername("user").
			WithPassword("user").
			WithAuthorities([]GrantedAuthority{Authority("ROLE_USER")}).Build()
		auth := UsernamePasswordAuthenticationToken{}.NewAuthenticated(user, user.GetPassword(), user.GetAuthorities())
		Expect(auth.IsAuthenticated()).To(BeTrue())
		Expect(auth.GetPrincipal()).NotTo(BeNil())
		Expect(auth.GetAuthorities()).NotTo(BeEmpty())

		Expect(auth.GetCredentials()).NotTo(BeNil())
		auth.EraseCredentials()
		Expect(auth.GetCredentials()).To(BeNil())

		Expect(auth.GetName()).NotTo(BeEmpty())
	})
})

var _ = Describe("AnonymousAuthenticationToken", func() {
	It("can be created", func() {
		auth := AnonymousAuthenticationToken{}.New()
		Expect(auth.GetCredentials()).To(BeEmpty())
	})
})

var _ = Describe("RememberMeAuthenticationToken", func() {
	It("can be created", func() {
		userDetailsService := InMemoryUserDetailsManager{}.New(DefaultPasswordEncoder)
		user := userDetailsService.NewUser().
			WithUsername("user").
			WithPassword("user").
			WithAuthorities([]GrantedAuthority{Authority("ROLE_USER")}).Build()
		auth := RememberMeAuthenticationToken{}.New("rememberme", user, user.GetAuthorities())
		Expect(auth.GetCredentials()).To(BeEmpty())
	})
})

var _ = Describe("InternalAuthenticationException", func() {
	It("can be declared", func() {
		err := InternalAuthenticationException{}.New("New error", AnonymousAuthenticationToken{}.New())
		Expect(err).To(HaveOccurred())
		Expect(err.AuthenticationRequest()).NotTo(BeNil())
	})
})

var _ = Describe("BadCredentialsException", func() {
	It("can be declared", func() {
		err := BadCredentialsException{}.New("New error", AnonymousAuthenticationToken{}.New())
		Expect(err).To(HaveOccurred())
	})
})

var _ = Describe("ProviderNotFoundException", func() {
	It("can be declared", func() {
		err := ProviderNotFoundException{}.New("New error", AnonymousAuthenticationToken{}.New())
		Expect(err).To(HaveOccurred())
	})
})

/*
var _ = Describe("AccountStatusError", func() {
	It("can be declared", func() {
		err := AccountStatusError{}.NewAccountStatusError("Error", "Error", AccountStatusExceptionCause{}.New().DISABLED)
		Expect(err.AccountStatus()).To(Equal(AccountStatusExceptionCause{}.New().DISABLED))
	})
})
*/

var _ = Describe("AccountExpiredException", func() {
	It("can be declared", func() {
		err := AccountExpiredException{}.New("Error", AnonymousAuthenticationToken{}.New())
		Expect(err).To(HaveOccurred())
		Expect(err.AccountStatus()).NotTo(BeNil())
	})
})

var _ = Describe("CredentialsExpiredException", func() {
	It("can be declared", func() {
		err := CredentialsExpiredException{}.New("Error", AnonymousAuthenticationToken{}.New())
		Expect(err).To(HaveOccurred())
	})
})

var _ = Describe("DisabledException", func() {
	It("can be declared", func() {
		err := DisabledException{}.New("Error", AnonymousAuthenticationToken{}.New())
		Expect(err).To(HaveOccurred())
	})
})

var _ = Describe("LockedException", func() {
	It("can be declared", func() {
		err := LockedException{}.New("Error", AnonymousAuthenticationToken{}.New())
		Expect(err).To(HaveOccurred())
	})
})
