package chain_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net/url"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	. "github.com/BeamFoundry/rays/pkg/core"
	. "github.com/BeamFoundry/rays/pkg/testing"
	. "github.com/BeamFoundry/rays/pkg/web"

	_ "github.com/BeamFoundry/rays-web-security/internal/autoconfig"
	. "github.com/BeamFoundry/rays-web-security/internal/chain"

	. "github.com/BeamFoundry/rays-web-security/pkg/auth"
	. "github.com/BeamFoundry/rays-web-security/pkg/config"
	. "github.com/BeamFoundry/rays-web-security/pkg/core"
	. "github.com/BeamFoundry/rays-web-security/pkg/password"
	. "github.com/BeamFoundry/rays-web-security/pkg/testing"
)

type PreAuthSecurityConfiguration struct {
	Configuration
	httpSecurityBuilder *HttpSecurityBuilder `@:"Inject"`
}

func (this *PreAuthSecurityConfiguration) HttpSecurity() *HttpSecurity {
	return this.httpSecurityBuilder.Build()
}

type PreAuthUserDetailsServiceConfiguration struct {
	Configuration
}

func (this *PreAuthUserDetailsServiceConfiguration) PreAuthUserDetailsService() AuthenticationUserDetailsService {
	return PreAuthenticatedGrantedAuthoritiesUserDetailsService{}.New()
}

type FailingPreAuthUserDetailsServiceConfiguration struct {
	Configuration
}

type failingPreAuthService struct{}

func (f *failingPreAuthService) LoadUserDetails(token Authentication) (UserDetails, AuthenticationException) {
	return nil, BadCredentialsException{}.New("user not found", token)
}

func (this *FailingPreAuthUserDetailsServiceConfiguration) PreAuthUserDetailsService() AuthenticationUserDetailsService {
	return &failingPreAuthService{}
}

var _ = Describe("PreAuthenticationFilter", func() {
	var chain SecurityFilterChain
	var app *MockSecurityAppHandler

	BeforeEach(func() {
		GetContainer().EnableScanning()

		builder := (&HttpSecurityBuilder{}).
			AuthorizedHTTPRequests().
			Paths("/api/admin/**").HasRole("ADMIN").
			Paths("/api/user/**").HasRole("USER").
			Paths("/api/cert/**").Authenticated().
			And().
			PreAuth().
			PrincipalHeader("X-Remote-User").
			CredentialsHeader("X-Remote-Creds").
			RolesHeader("X-Remote-Roles").
			RolesDelimiter(""). // Trigger default delim test
			And().
			SessionCreationPolicy().Stateless()

		AddBeamFor(builder)
		AddBeamFor(&PreAuthSecurityConfiguration{})
		Expect(GetContainer().Initialize()).NotTo(HaveOccurred())

		chain = GetBeamDefaultInstance[SecurityFilterChain]()
		Expect(chain).NotTo(BeNil())
		app = NewMockSecurityAppHandler()
		chain.Initialize("primary", app)
	})

	It("authenticates a request carrying principal and role headers and extracts credentials", func() {
		u := ValErr(url.Parse("http://www.example.com/api/admin/data"))
		handler := NewMockSecurityHandler(HttpMethods.GET, u)
		handler.SetHeader("X-Remote-User", "admin-user")
		handler.SetHeader("X-Remote-Creds", "secret-token")
		handler.SetHeader("X-Remote-Roles", "ROLE_ADMIN,ROLE_USER")

		err := app.Execute(handler)
		Expect(err).NotTo(HaveOccurred())

		contextHolder := GetBeamDefaultInstance[SecurityContextHolder]()
		auth := contextHolder.GetContext().GetAuthentication()
		Expect(auth.IsAuthenticated()).To(BeTrue())
		user, ok := auth.GetPrincipal().(UserDetails)
		Expect(ok).To(BeTrue())
		Expect(user.GetUsername()).To(Equal("admin-user"))
	})

	It("rejects access to protected path when roles are insufficient", func() {
		u := ValErr(url.Parse("http://www.example.com/api/admin/data"))
		handler := NewMockSecurityHandler(HttpMethods.GET, u)
		handler.SetHeader("X-Remote-User", "regular-user")
		handler.SetHeader("X-Remote-Roles", "ROLE_USER")

		err := app.Execute(handler)
		Expect(err).To(HaveOccurred())
		var ex *DefaultSecurityFilterChainException
		Expect(errors.As(err, &ex)).To(BeTrue())
		Expect(ex.Status()).To(Equal(403))
	})

	It("falls back to mTLS certificate when headers are absent and ensures untrusted headers cannot override cert", func() {
		u := ValErr(url.Parse("http://www.example.com/api/cert/profile"))
		handler := NewMockSecurityHandler(HttpMethods.GET, u)

		cert := &x509.Certificate{
			Subject: pkix.Name{
				CommonName: "client-cert-user",
			},
		}
		handler.Req.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{cert},
			VerifiedChains:   [][]*x509.Certificate{{cert}},
		}
		// Attempting to override identity or inject header roles during cert authentication should be ignored
		handler.SetHeader("X-Remote-User", "spoofed-admin")
		handler.SetHeader("X-Remote-Roles", "ROLE_USER")

		err := app.Execute(handler)
		Expect(err).NotTo(HaveOccurred())

		contextHolder := GetBeamDefaultInstance[SecurityContextHolder]()
		auth := contextHolder.GetContext().GetAuthentication()
		Expect(auth.IsAuthenticated()).To(BeTrue())
		Expect(auth.GetAuthorities()).To(BeEmpty()) // Authorities from header were cleared
		user, ok := auth.GetPrincipal().(UserDetails)
		Expect(ok).To(BeTrue())
		Expect(user.GetUsername()).To(Equal("client-cert-user"))
		Expect(user.GetUsername()).NotTo(Equal("spoofed-admin"))
	})

	It("rejects mTLS fallback when request-supplied roles in headers are needed for role-protected path", func() {
		u := ValErr(url.Parse("http://www.example.com/api/user/profile"))
		handler := NewMockSecurityHandler(HttpMethods.GET, u)

		cert := &x509.Certificate{
			Subject: pkix.Name{
				CommonName: "client-cert-user",
			},
		}
		handler.Req.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{cert},
			VerifiedChains:   [][]*x509.Certificate{{cert}},
		}
		handler.SetHeader("X-Remote-Roles", "ROLE_USER")

		err := app.Execute(handler)
		Expect(err).To(HaveOccurred())
		var ex *DefaultSecurityFilterChainException
		Expect(errors.As(err, &ex)).To(BeTrue())
		Expect(ex.Status()).To(Equal(403))
	})

	It("falls back to mTLS email address when CommonName is empty", func() {
		u := ValErr(url.Parse("http://www.example.com/api/cert/profile"))
		handler := NewMockSecurityHandler(HttpMethods.GET, u)

		cert := &x509.Certificate{
			EmailAddresses: []string{"cert-email@example.com"},
		}
		handler.Req.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{cert},
			VerifiedChains:   [][]*x509.Certificate{{cert}},
		}

		err := app.Execute(handler)
		Expect(err).NotTo(HaveOccurred())

		contextHolder := GetBeamDefaultInstance[SecurityContextHolder]()
		auth := contextHolder.GetContext().GetAuthentication()
		Expect(auth.IsAuthenticated()).To(BeTrue())
		user, ok := auth.GetPrincipal().(UserDetails)
		Expect(ok).To(BeTrue())
		Expect(user.GetUsername()).To(Equal("cert-email@example.com"))
	})

	It("falls back to mTLS Subject.String() when CommonName and EmailAddresses are empty", func() {
		u := ValErr(url.Parse("http://www.example.com/api/cert/profile"))
		handler := NewMockSecurityHandler(HttpMethods.GET, u)

		cert := &x509.Certificate{
			Subject: pkix.Name{
				Organization: []string{"AcmeCorp"},
			},
		}
		handler.Req.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{cert},
			VerifiedChains:   [][]*x509.Certificate{{cert}},
		}

		err := app.Execute(handler)
		Expect(err).NotTo(HaveOccurred())

		contextHolder := GetBeamDefaultInstance[SecurityContextHolder]()
		auth := contextHolder.GetContext().GetAuthentication()
		Expect(auth.IsAuthenticated()).To(BeTrue())
		user, ok := auth.GetPrincipal().(UserDetails)
		Expect(ok).To(BeTrue())
		Expect(user.GetUsername()).To(Equal(cert.Subject.String()))
	})

	It("ignores mTLS certificate when VerifiedChains is empty", func() {
		u := ValErr(url.Parse("http://www.example.com/api/cert/profile"))
		handler := NewMockSecurityHandler(HttpMethods.GET, u)

		cert := &x509.Certificate{
			Subject: pkix.Name{
				CommonName: "unverified-client",
			},
		}
		handler.Req.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{cert},
			VerifiedChains:   nil, // unverified chain
		}

		err := app.Execute(handler)
		Expect(err).To(HaveOccurred())
		var ex *DefaultSecurityFilterChainException
		Expect(errors.As(err, &ex)).To(BeTrue())
		Expect(ex.Status()).To(Equal(403))
	})

	It("returns 403 when unauthenticated request accesses restricted path", func() {
		u := ValErr(url.Parse("http://www.example.com/api/admin/data"))
		handler := NewMockSecurityHandler(HttpMethods.GET, u)

		err := app.Execute(handler)
		Expect(err).To(HaveOccurred())
		var ex *DefaultSecurityFilterChainException
		Expect(errors.As(err, &ex)).To(BeTrue())
		Expect(ex.Status()).To(Equal(403))
	})
})

var _ = Describe("PreAuthFilter Edge Cases and Additional Capabilities", func() {
	It("returns error when ExceptionOnMissing is true and header is missing", func() {
		GetContainer().EnableScanning()

		builder := (&HttpSecurityBuilder{}).
			PreAuth().
			PrincipalHeader("X-Remote-User").
			ExceptionOnMissing(true).
			And().
			SessionCreationPolicy().Stateless()

		AddBeamFor(builder)
		AddBeamFor(&PreAuthSecurityConfiguration{})
		Expect(GetContainer().Initialize()).NotTo(HaveOccurred())

		chain := GetBeamDefaultInstance[SecurityFilterChain]()
		app := NewMockSecurityAppHandler()
		chain.Initialize("primary", app)

		u := ValErr(url.Parse("http://www.example.com/any"))
		handler := NewMockSecurityHandler(HttpMethods.GET, u)
		err := app.Execute(handler)
		Expect(err).To(HaveOccurred())
		var ex *DefaultSecurityFilterChainException
		Expect(errors.As(err, &ex)).To(BeTrue())
		Expect(ex.Status()).To(Equal(403))
	})

	It("returns Next when PreAuth is nil on HttpSecurity", func() {
		filter := &PreAuthFilter{}
		ex := filter.Authenticate(nil)
		Expect(ex.Action()).To(Equal(DefaultSecurityFilterAction{}.New().NEXT.Name()))
	})

	It("returns 403 in AuthenticationRequired", func() {
		filter := &PreAuthFilter{}
		ex := filter.AuthenticationRequired(nil)
		var dex *DefaultSecurityFilterChainException
		Expect(errors.As(ex, &dex)).To(BeTrue())
		Expect(dex.Status()).To(Equal(403))
	})

	It("returns error in WithContext if parent is not HttpSecurity", func() {
		filter := &PreAuthFilter{}
		ctx := context.WithValue(context.Background(), PrototypeContextParentInstance, "not-http-security")
		err := filter.WithContext(ctx)
		Expect(err).To(HaveOccurred())
	})

	It("does not include PreAuthFilter in HttpSecurity filters when PreAuth is not configured", func() {
		GetContainer().EnableScanning()
		builder := (&HttpSecurityBuilder{}).AnyRequest().PermitAll()
		AddBeamFor(builder)
		AddBeamFor(&PreAuthSecurityConfiguration{})
		Expect(GetContainer().Initialize()).NotTo(HaveOccurred())

		httpSecurity := GetBeamDefaultInstance[*HttpSecurity]()
		Expect(httpSecurity).NotTo(BeNil())
		Expect(httpSecurity.PreAuth()).To(BeNil())

		for _, filter := range httpSecurity.Filters() {
			_, isPreAuth := filter.(*PreAuthFilter)
			Expect(isPreAuth).To(BeFalse(), "PreAuthFilter should NOT be loaded when PreAuth is not configured")
		}
	})

	It("handles non-validation error in FormLoginFilter.BindErrorMessage", func() {
		filter := &FormLoginFilter{}
		data := filter.BindErrorMessage("myform", errors.New("generic bind error"))
		Expect(data["Error"]).To(Equal("generic bind error"))
	})

	It("returns 403 when AuthenticationManager fails authentication", func() {
		GetContainer().EnableScanning()
		AddBeamFor(&FailingPreAuthUserDetailsServiceConfiguration{})

		builder := (&HttpSecurityBuilder{}).
			AuthorizedHTTPRequests().
			Paths("/api/test/**").PermitAll().
			And().
			PreAuth().
			PrincipalHeader("X-Remote-User").
			And().
			SessionCreationPolicy().Stateless()

		AddBeamFor(builder)
		AddBeamFor(&PreAuthSecurityConfiguration{})
		Expect(GetContainer().Initialize()).NotTo(HaveOccurred())

		c := GetBeamDefaultInstance[SecurityFilterChain]()
		a := NewMockSecurityAppHandler()
		c.Initialize("primary", a)

		u := ValErr(url.Parse("http://www.example.com/api/test"))
		h := NewMockSecurityHandler(HttpMethods.GET, u)
		h.SetHeader("X-Remote-User", "unknown_user")
		err := a.Execute(h)
		Expect(err).To(HaveOccurred())
		var ex *DefaultSecurityFilterChainException
		Expect(errors.As(err, &ex)).To(BeTrue())
		Expect(ex.Status()).To(Equal(403))
	})

	It("accepts pre-auth headers from a verified trusted proxy", func() {
		GetContainer().EnableScanning()

		builder := (&HttpSecurityBuilder{}).
			AuthorizedHTTPRequests().
			Paths("/api/proxy/**").Authenticated().
			And().
			PreAuth().
			PrincipalHeader("X-Remote-User").
			TrustedProxies("proxy.internal").
			And().
			SessionCreationPolicy().Stateless()

		AddBeamFor(builder)
		AddBeamFor(&PreAuthSecurityConfiguration{})
		Expect(GetContainer().Initialize()).NotTo(HaveOccurred())

		c := GetBeamDefaultInstance[SecurityFilterChain]()
		a := NewMockSecurityAppHandler()
		c.Initialize("primary", a)

		u := ValErr(url.Parse("http://www.example.com/api/proxy/data"))
		h := NewMockSecurityHandler(HttpMethods.GET, u)
		proxyCert := &x509.Certificate{
			Subject: pkix.Name{CommonName: "proxy.internal"},
		}
		h.Req.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{proxyCert},
			VerifiedChains:   [][]*x509.Certificate{{proxyCert}},
		}
		h.SetHeader("X-Remote-User", "forwarded-alice")

		err := a.Execute(h)
		Expect(err).NotTo(HaveOccurred())

		contextHolder := GetBeamDefaultInstance[SecurityContextHolder]()
		auth := contextHolder.GetContext().GetAuthentication()
		Expect(auth.IsAuthenticated()).To(BeTrue())
		Expect(auth.GetPrincipal().(UserDetails).GetUsername()).To(Equal("forwarded-alice"))
	})

	It("rejects pre-auth headers when connection is not from a trusted proxy", func() {
		GetContainer().EnableScanning()

		builder := (&HttpSecurityBuilder{}).
			AuthorizedHTTPRequests().
			Paths("/api/proxy/**").Authenticated().
			And().
			PreAuth().
			PrincipalHeader("X-Remote-User").
			TrustedProxies("proxy.internal").
			AllowMtlsFallback(false).
			ExceptionOnMissing(true).
			And().
			SessionCreationPolicy().Stateless()

		AddBeamFor(builder)
		AddBeamFor(&PreAuthSecurityConfiguration{})
		Expect(GetContainer().Initialize()).NotTo(HaveOccurred())

		c := GetBeamDefaultInstance[SecurityFilterChain]()
		a := NewMockSecurityAppHandler()
		c.Initialize("primary", a)

		// Request without cert (untrusted connection)
		u := ValErr(url.Parse("http://www.example.com/api/proxy/data"))
		h := NewMockSecurityHandler(HttpMethods.GET, u)
		h.SetHeader("X-Remote-User", "spoofed-user")

		err := a.Execute(h)
		Expect(err).To(HaveOccurred())
		var ex *DefaultSecurityFilterChainException
		Expect(errors.As(err, &ex)).To(BeTrue())
		Expect(ex.Status()).To(Equal(403))
	})

	It("rejects request with a trusted proxy certificate when no principal header is provided on an authenticated path", func() {
		GetContainer().EnableScanning()

		builder := (&HttpSecurityBuilder{}).
			AuthorizedHTTPRequests().
			Paths("/api/proxy/**").Authenticated().
			And().
			PreAuth().
			PrincipalHeader("X-Remote-User").
			TrustedProxies("proxy.internal").
			AllowMtlsFallback(true).
			And().
			SessionCreationPolicy().Stateless()

		AddBeamFor(builder)
		AddBeamFor(&PreAuthSecurityConfiguration{})
		Expect(GetContainer().Initialize()).NotTo(HaveOccurred())

		c := GetBeamDefaultInstance[SecurityFilterChain]()
		a := NewMockSecurityAppHandler()
		c.Initialize("primary", a)

		u := ValErr(url.Parse("http://www.example.com/api/proxy/data"))
		h := NewMockSecurityHandler(HttpMethods.GET, u)
		proxyCert := &x509.Certificate{
			Subject: pkix.Name{CommonName: "proxy.internal"},
		}
		h.Req.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{proxyCert},
			VerifiedChains:   [][]*x509.Certificate{{proxyCert}},
		}

		err := a.Execute(h)
		Expect(err).To(HaveOccurred())
		var ex *DefaultSecurityFilterChainException
		Expect(errors.As(err, &ex)).To(BeTrue())
		Expect(ex.Status()).To(Equal(403))
	})

	It("allows overriding default AuthenticationUserDetailsService with a custom beam", func() {
		GetContainer().EnableScanning()
		AddBeamFor(&PreAuthUserDetailsServiceConfiguration{})

		builder := (&HttpSecurityBuilder{}).
			AuthorizedHTTPRequests().
			Paths("/api/custom/**").Authenticated().
			And().
			PreAuth().
			PrincipalHeader("X-Remote-User").
			And().
			SessionCreationPolicy().Stateless()

		AddBeamFor(builder)
		AddBeamFor(&PreAuthSecurityConfiguration{})
		Expect(GetContainer().Initialize()).NotTo(HaveOccurred())

		c := GetBeamDefaultInstance[SecurityFilterChain]()
		a := NewMockSecurityAppHandler()
		c.Initialize("primary", a)

		u := ValErr(url.Parse("http://www.example.com/api/custom/resource"))
		h := NewMockSecurityHandler(HttpMethods.GET, u)
		h.SetHeader("X-Remote-User", "custom-alice")

		err := a.Execute(h)
		Expect(err).NotTo(HaveOccurred())

		contextHolder := GetBeamDefaultInstance[SecurityContextHolder]()
		auth := contextHolder.GetContext().GetAuthentication()
		Expect(auth.IsAuthenticated()).To(BeTrue())
		Expect(auth.GetPrincipal().(UserDetails).GetUsername()).To(Equal("custom-alice"))
	})

	It("automatically wraps UserDetailsService bean when present in the container", func() {
		GetContainer().EnableScanning()
		uds := InMemoryUserDetailsManager{}.New(NoOpPasswordEncoder{}.New())
		_ = uds.NewUser().
			WithUsername("db-user").
			WithPassword("secret").
			WithAuthorities([]GrantedAuthority{Authority("ROLE_USER")}).
			Build()
		AddBeamFor(uds)

		builder := (&HttpSecurityBuilder{}).
			AuthorizedHTTPRequests().
			Paths("/api/db/**").HasRole("USER").
			And().
			PreAuth().
			PrincipalHeader("X-Remote-User").
			And().
			SessionCreationPolicy().Stateless()

		AddBeamFor(builder)
		AddBeamFor(&PreAuthSecurityConfiguration{})
		Expect(GetContainer().Initialize()).NotTo(HaveOccurred())

		c := GetBeamDefaultInstance[SecurityFilterChain]()
		a := NewMockSecurityAppHandler()
		c.Initialize("primary", a)

		u := ValErr(url.Parse("http://www.example.com/api/db/profile"))
		h := NewMockSecurityHandler(HttpMethods.GET, u)
		h.SetHeader("X-Remote-User", "db-user")

		err := a.Execute(h)
		Expect(err).NotTo(HaveOccurred())

		contextHolder := GetBeamDefaultInstance[SecurityContextHolder]()
		auth := contextHolder.GetContext().GetAuthentication()
		Expect(auth.IsAuthenticated()).To(BeTrue())
		Expect(auth.GetPrincipal().(UserDetails).GetUsername()).To(Equal("db-user"))

		// Also verify unmapped db-user fails authentication
		hBad := NewMockSecurityHandler(HttpMethods.GET, u)
		hBad.SetHeader("X-Remote-User", "missing-db-user")
		errBad := a.Execute(hBad)
		Expect(errBad).To(HaveOccurred())
	})
})
