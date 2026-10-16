package config_test

import (
	"testing"

	. "github.com/BeamFoundry/rays/pkg/core"
	. "github.com/BeamFoundry/rays/pkg/testing"
	. "github.com/BeamFoundry/rays/pkg/web"

	_ "github.com/BeamFoundry/rays-web-security/internal/autoconfig"

	. "github.com/BeamFoundry/rays-web-security/pkg/auth"
	. "github.com/BeamFoundry/rays-web-security/pkg/config"
	. "github.com/BeamFoundry/rays-web-security/pkg/core"
	. "github.com/BeamFoundry/rays-web-security/pkg/rememberme"
	. "github.com/BeamFoundry/rays-web-security/pkg/testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestConfig(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Config Suite")
}

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
		WithAuthorities([]GrantedAuthority{Authority("ROLE_USER"), Authority("ROLE_PRIVILEGED")}).Build()
	userDetailsService.NewUser().
		WithUsername("admin").
		WithPassword("admin").
		WithAuthorities([]GrantedAuthority{Authority("ROLE_USER"), Authority("ROLE_ADMIN")}).Build()
	return userDetailsService
}

func (this *UserDetailsServiceConfiguration) RememberMe(
	that struct {
		userDetailsService UserDetailsService `@:"Inject"`
	},
) *TokenBasedRememberMeService {
	return TokenBasedRememberMeService{}.New("secret", that.userDetailsService)
}

type HttpSecurityConfiguration struct {
	Configuration
	rememberMe   RememberMeService    `@:"Inject"`
	httpSecurity *HttpSecurityBuilder `@:"Inject"`
}

func (this *HttpSecurityConfiguration) HttpSecurity() *HttpSecurity {
	return this.httpSecurity.RememberMe(this.rememberMe).Build()
}

var _ = Describe("HTTPSecurity", func() {
	It("can be build", func() {
		httpSecurityBuilder := (&HttpSecurityBuilder{}).
			Match("/**").
			AuthorizedHTTPRequests().
			Paths("/anonymous").Anonymous().
			Paths("/authenticated").Authenticated().
			And().
			AnyRequest().DenyAll().
			FormLogin().
			ViewName("views/login").
			And().
			Basic().
			Csrf().Disable()
		GetContainer().EnableScanning()
		AddBeamFor(httpSecurityBuilder)
		AddBeamFor(&HttpSecurityConfiguration{})
		AddBeamFor(&UserDetailsServiceConfiguration{})
		Expect(GetContainer().Initialize()).NotTo(HaveOccurred())
		httpSecurity := GetBeamDefaultInstance[*HttpSecurity]()
		Expect(httpSecurity.Filters()).NotTo(BeEmpty())
		Expect(httpSecurity.RememberMeService()).NotTo(BeNil())
	})
})

var _ = Describe("AuthorizedHTTPRequest", func() {
	It("can be build in HTTPSecurity", func() {
		httpSecurity := (&HttpSecurityBuilder{}).
			Match("/*", "/static/**").
			AuthorizedHTTPRequests().
			Paths("/anonymous").Anonymous().
			Method(HttpMethods.TRACE).DenyAll().
			MethodAndPaths(HttpMethods.TRACE, "/permitall").PermitAll().
			Paths("/profile", "/authenticated").Authenticated().
			Paths("/any_auth").HasAnyAuthority([]string{"AUTH_1"}).
			Paths("/any_role").HasAnyRole([]string{"ROLE_1"}).
			Paths("/privileged").HasAuthority("ROLE_PRIVILEGED").
			Paths("/admin").HasRole("ADMIN").
			And().
			// AnyRequest().PermitAll().
			Build()
		Expect(httpSecurity).NotTo(BeNil())
		Expect(httpSecurity.AuthorizedHTTPRequests()[0].Matcher().Match("GET", "/anonymous")).To(BeTrue())
		Expect(httpSecurity.SessionCreationPolicy()).To(Equal(SessionCreationPolicy{}.New().IF_REQUIRED))

		AddBeamFor(&UserDetailsServiceConfiguration{})
		GetContainer().EnableScanning()
		Expect(GetContainer().Initialize()).NotTo(HaveOccurred())

		manager := GetBeamDefaultInstance[AuthenticationManager]()
		Expect(manager).NotTo(BeNil())

		anonymous := AnonymousAuthenticationToken{}.New()
		privileged, err := manager.Authenticate(UsernamePasswordAuthenticationToken{}.New("user", "user"))
		Expect(err).NotTo(HaveOccurred())
		admin, err := manager.Authenticate(UsernamePasswordAuthenticationToken{}.New("admin", "admin"))
		Expect(err).NotTo(HaveOccurred())

		Expect(httpSecurity.DefaultHTTPPolicy()).NotTo(BeNil())
		Expect(httpSecurity.Matchers()).NotTo(BeEmpty())
		for _, request := range httpSecurity.AuthorizedHTTPRequests() {
			Expect(request.Matcher().String()).NotTo(BeEmpty())
			Expect(request.Policy().String()).NotTo(BeEmpty())
		}
		Expect(httpSecurity.AuthorizedHTTPRequests()[0].Matcher().Match("GET", "/anonymous")).To(BeTrue())
		Expect(httpSecurity.AuthorizedHTTPRequests()[0].Policy().Allow(anonymous)).To(BeTrue())

		Expect(httpSecurity.AuthorizedHTTPRequests()[1].Matcher().Match("TRACE", "/deny")).To(BeTrue())
		Expect(httpSecurity.AuthorizedHTTPRequests()[1].Matcher().Match("GET", "/deny")).To(BeFalse())
		Expect(httpSecurity.AuthorizedHTTPRequests()[1].Policy().Allow(anonymous)).To(BeFalse())

		Expect(httpSecurity.AuthorizedHTTPRequests()[2].Matcher().Match("TRACE", "/permitall")).To(BeTrue())
		Expect(httpSecurity.AuthorizedHTTPRequests()[2].Matcher().Match("GET", "/permitall")).To(BeFalse())
		Expect(httpSecurity.AuthorizedHTTPRequests()[2].Policy().Allow(anonymous)).To(BeTrue())

		Expect(httpSecurity.AuthorizedHTTPRequests()[3].Policy().Allow(anonymous)).To(BeFalse())
		Expect(httpSecurity.AuthorizedHTTPRequests()[4].Policy().Allow(anonymous)).To(BeFalse())
		Expect(httpSecurity.AuthorizedHTTPRequests()[5].Policy().Allow(anonymous)).To(BeFalse())

		Expect(httpSecurity.AuthorizedHTTPRequests()[6].Policy().Allow(anonymous)).To(BeFalse())
		Expect(httpSecurity.AuthorizedHTTPRequests()[6].Policy().Allow(privileged)).To(BeTrue())
		Expect(httpSecurity.AuthorizedHTTPRequests()[7].Policy().Allow(anonymous)).To(BeFalse())
		Expect(httpSecurity.AuthorizedHTTPRequests()[7].Policy().Allow(admin)).To(BeTrue())
	})
})

var _ = Describe("Csrf", func() {
	It("can be build in HTTPSecurityBuilder", func() {
		httpSecurity := (&HttpSecurityBuilder{}).
			AnyRequest().PermitAll().
			Csrf().Disable().
			Build()
		Expect(httpSecurity).NotTo(BeNil())
		Expect(httpSecurity.Csrf().Disabled()).To(BeTrue())
	})
})

var _ = Describe("FormLogin", func() {
	It("can be build in HTTPSecurityBuilder", func() {
		httpSecurity := (&HttpSecurityBuilder{}).
			AuthorizedHTTPRequests().
			Paths("/profile").Authenticated().
			Paths("/login").PermitAll().
			And().
			AnyRequest().DenyAll().
			FormLogin().
			Username("username").
			Password("password").
			LoginPath("/login").
			LogoutPath("/logout").
			ViewName("login").
			DefaultSuccessUrl("/").
			And().Build()
		Expect(httpSecurity).NotTo(BeNil())
		formLogin := httpSecurity.FormLogin()
		Expect(formLogin).NotTo(BeNil())
		Expect(formLogin.Username()).NotTo(BeEmpty())
		Expect(formLogin.Password()).NotTo(BeEmpty())
		Expect(formLogin.LoginPath()).NotTo(BeEmpty())
		Expect(formLogin.LogoutPath()).NotTo(BeEmpty())
		Expect(formLogin.ViewName()).NotTo(BeEmpty())
		Expect(formLogin.DefaultSuccessURL()).NotTo(BeEmpty())
	})
})

type Optioner struct {
	httpSecurityBuilder *HttpSecurityBuilder
}

func (this *Optioner) And() *HttpSecurityBuilder {
	return this.httpSecurityBuilder
}

func (this *Optioner) Activate() *Optioner {
	return this
}

func Option(h *HttpSecurityBuilder) *Optioner {
	return &Optioner{httpSecurityBuilder: h}
}

var _ = Describe("With", func() {
	Expect((&HttpSecurityBuilder{}).With(Option).Activate().And()).NotTo(BeNil())
})

type NilSecurityFilter struct{}

var _ SecurityFilter = &NilSecurityFilter{}

// Authenticate implements [security.SecurityFilter].
func (n *NilSecurityFilter) Authenticate(_ SecurityHandler) SecurityFilterChainException {
	panic("unimplemented")
}

// AuthenticationRequired implements [security.SecurityFilter].
func (n *NilSecurityFilter) AuthenticationRequired(_ SecurityHandler) SecurityFilterChainException {
	panic("unimplemented")
}

var _ = Describe("Misc", func() {
	It("can be defined", func() {
		httpSecurity := (&HttpSecurityBuilder{}).
			AddCustomFilter(&NilSecurityFilter{}).
			AnyRequest().PermitAll().
			SessionCreationPolicy().Default().
			SessionCreationPolicy().Always().
			SessionCreationPolicy().IfRequired().
			SessionCreationPolicy().Never().
			SessionCreationPolicy().Stateless().Build()
		Expect(httpSecurity).NotTo(BeNil())
	})
})
