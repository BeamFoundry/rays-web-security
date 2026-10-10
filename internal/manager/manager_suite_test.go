package manager_test

import (
	"testing"

	. "github.com/BeamFoundry/rays/pkg/core"
	. "github.com/BeamFoundry/rays/pkg/testing"

	_ "github.com/BeamFoundry/rays-web-security/internal/autoconfig"

	. "github.com/BeamFoundry/rays-web-security/internal/manager"
	. "github.com/BeamFoundry/rays-web-security/pkg/auth"
	. "github.com/BeamFoundry/rays-web-security/pkg/core"
	. "github.com/BeamFoundry/rays-web-security/pkg/testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestManager(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Internal/Manager Suite")
}

type ErrorUserDetailService struct{}

func (e *ErrorUserDetailService) LoadUserByUsername(string) UserDetails {
	panic("unimplemented")
}

var _ UserDetailsService = &ErrorUserDetailService{}

type UserDetailsServiceConfiguration struct {
	Configuration
}

func (this *UserDetailsServiceConfiguration) UserDetailsService(
	that struct {
		passwordEncoder PasswordEncoder `@:"Inject"`
	},
) UserDetailsService {
	userDetailsService := InMemoryUserDetailsManager{}.New(that.passwordEncoder)
	userDetailsService.NewUser().
		WithUsername("user").
		WithPassword("user").
		WithAuthorities([]GrantedAuthority{Authority("ROLE_USER")}).Build()
	userDetailsService.NewUser().
		WithUsername("locked").
		WithPassword("locked").
		SetLocked(true).
		WithAuthorities([]GrantedAuthority{Authority("ROLE_USER")}).Build()
	return userDetailsService
}

var _ = Describe("AuthenticationAuthenticationManager", func() {
	Context("With an UserDetailsService", func() {
		It("can authenticate a user", func() {
			AddBeamFor(&UserDetailsServiceConfiguration{})
			GetContainer().EnableScanning()
			Expect(GetContainer().Initialize()).NotTo(HaveOccurred())

			manager := GetBeamDefaultInstance[AuthenticationManager]()
			Expect(manager).NotTo(BeNil())

			user, err := manager.Authenticate(UsernamePasswordAuthenticationToken{}.New("user", "user"))
			Expect(err).NotTo(HaveOccurred())
			Expect(user.IsAuthenticated()).To(BeTrue())
			Expect(user.GetName()).NotTo(BeEmpty())
			Expect(user.GetAuthorities()).NotTo(BeEmpty())
			Expect(user.GetPrincipal()).NotTo(BeNil())

			_, err = manager.Authenticate(UsernamePasswordAuthenticationToken{}.New("user", "bad"))
			Expect(err).To(HaveOccurred())
			_, err = manager.Authenticate(UsernamePasswordAuthenticationToken{}.New("bad", "bad"))
			Expect(err).To(HaveOccurred())

			_, err = manager.Authenticate(UsernamePasswordAuthenticationToken{}.New("locked", "locked"))
			Expect(err).To(HaveOccurred())
		})
	})

	Context("Without an UserDetailsService & UserDetailsAuthenticationProvider", func() {
		It("will return an error", func() {
			GetContainer().EnableScanning()
			Expect(GetContainer().Initialize()).NotTo(HaveOccurred())

			manager := GetBeamDefaultInstance[AuthenticationManager]()
			Expect(manager).NotTo(BeNil())
			_, err := manager.Authenticate(UsernamePasswordAuthenticationToken{}.New("user", "bad"))
			Expect(err).To(HaveOccurred())
		})
	})

	Context("Without an UserDetailsService", func() {
		It("will return an error", func() {
			AddBeamFor(&UserDetailsAuthenticationProvider{})
			GetContainer().EnableScanning()
			Expect(GetContainer().Initialize()).NotTo(HaveOccurred())

			manager := GetBeamDefaultInstance[AuthenticationManager]()
			Expect(manager).NotTo(BeNil())
			_, err := manager.Authenticate(UsernamePasswordAuthenticationToken{}.New("user", "bad"))
			Expect(err).To(HaveOccurred())
		})
	})

	Context("With a failing UserDetailsService", func() {
		It("will return an error", func() {
			userDetailsService := &ErrorUserDetailService{}
			AddBeamFor(userDetailsService)
			AddBeamFor(UserDetailsAuthenticationProvider{}.New(userDetailsService))
			GetContainer().EnableScanning()
			Expect(GetContainer().Initialize()).NotTo(HaveOccurred())
			manager := GetBeamDefaultInstance[AuthenticationManager]()
			Expect(manager).NotTo(BeNil())
			_, err := manager.Authenticate(UsernamePasswordAuthenticationToken{}.New("user", "bad"))
			Expect(err).To(HaveOccurred())
		})
	})

	Context("With an AnonymousAuthenticationToken", func() {
		It("will pass the authentication", func() {
			GetContainer().EnableScanning()
			Expect(GetContainer().Initialize()).NotTo(HaveOccurred())
			manager := GetBeamDefaultInstance[AuthenticationManager]()
			Expect(manager).NotTo(BeNil())
			user, err := manager.Authenticate(AnonymousAuthenticationToken{}.New())
			Expect(err).NotTo(HaveOccurred())
			Expect(user.IsAuthenticated()).To(BeFalse())
			Expect(user.GetName()).NotTo(BeEmpty())
			Expect(user.GetCredentials()).To(BeEmpty())
		})
	})

	Context("With an RememberMeAuthenticationToken", func() {
		It("will pass the authentication", func() {
			GetContainer().EnableScanning()
			Expect(GetContainer().Initialize()).NotTo(HaveOccurred())
			manager := GetBeamDefaultInstance[AuthenticationManager]()
			Expect(manager).NotTo(BeNil())
			user, err := manager.Authenticate(RememberMeAuthenticationToken{}.New("test", "test", []GrantedAuthority{Authority("ROLE_USER")}))
			Expect(err).NotTo(HaveOccurred())
			Expect(user.IsAuthenticated()).To(BeTrue())
			Expect(user.GetName()).NotTo(BeEmpty())
			Expect(user.GetCredentials()).To(BeEmpty())
		})
	})
})
