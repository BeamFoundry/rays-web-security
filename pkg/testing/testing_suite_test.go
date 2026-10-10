package testing_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	_ "github.com/BeamFoundry/rays-web-security/internal/autoconfig"

	. "github.com/BeamFoundry/rays-web-security/pkg/core"
	. "github.com/BeamFoundry/rays-web-security/pkg/password"
	. "github.com/BeamFoundry/rays-web-security/pkg/testing"
)

func TestTesting(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Testing Suite")
}

var DefaultPasswordEncoder PasswordEncoder = DelegatingPasswordEncoder{}.New(
	"bcrypt", map[string]PasswordEncoder{"bcrypt": BCryptPasswordEncoder{}.New(10)},
)

var _ = Describe("In memory user management", func() {
	Describe("InMemoryUserDetailsManager", func() {
		It("can create a user", func() {
			userDetailsService := InMemoryUserDetailsManager{}.New(DefaultPasswordEncoder)
			user := userDetailsService.NewUser().
				WithUsername("user").
				WithPassword("user").
				SetAccountExpired(false).
				SetCredentialsExpired(false).
				SetDisabled(false).
				SetLocked(false).
				WithAuthorities([]GrantedAuthority{Authority("ROLE_USER"), Authority("ROLE_PRIVILEGED")}).Build()
			Expect(user.GetUsername()).NotTo(BeEmpty())
			Expect(user.GetPassword()).NotTo(BeEmpty())
			Expect(user.GetAuthorities()).NotTo(BeEmpty())
			Expect(user.IsExpired()).To(BeFalse())
			Expect(user.IsCredentialExpired()).To(BeFalse())
			Expect(user.IsDisabled()).To(BeFalse())
			Expect(user.IsLocked()).To(BeFalse())
			Expect(userDetailsService.LoadUserByUsername("user")).NotTo(BeNil())
			Expect(userDetailsService.LoadUserByUsername("admin")).To(BeNil())
		})
	})
})
