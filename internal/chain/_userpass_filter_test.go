package chain_test

import (
	"encoding/base64"
	"net/url"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	. "github.com/BeamFoundry/rays/pkg/i18n"
	. "github.com/BeamFoundry/rays/pkg/i18n/locales"
	. "github.com/BeamFoundry/rays/pkg/lang"
	. "github.com/BeamFoundry/rays/pkg/testing"

	. "github.com/BeamFoundry/rays-web-security/internal/chain"
	. "github.com/BeamFoundry/rays-web-security/pkg/config"
	. "github.com/BeamFoundry/rays-web-security/pkg/core"
	. "github.com/BeamFoundry/rays-web-security/pkg/rememberme"
	. "github.com/BeamFoundry/rays-web-security/pkg/testing"

	"github.com/go-playground/validator/v10/translations/en"
)

var _ = Describe("UsernamePasswordAuthenticationFilter", func() {
	BeforeEach(func() {
		userDetailsService := InMemoryUserDetailsManager{}.New(DefaultPasswordEncoder)
		userDetailsService.NewUser().
			WithUsername("user").
			WithPassword("user").
			WithAuthorities([]GrantedAuthority{Authority("ROLE_USER"), Authority("ROLE_PRIVILEGED")}).Build()
		userDetailsService.NewUser().
			WithUsername("admin").
			WithPassword("admin").
			WithAuthorities([]GrantedAuthority{Authority("ROLE_USER"), Authority("ROLE_ADMIN")}).Build()
		AddBeamFor(userDetailsService)

		userDetailsAuthenticationProvider := UserDetailsAuthenticationProvider{}.New(userDetailsService)
		userDetailsAuthenticationProvider.SetEncoder(DefaultPasswordEncoder)
		AddBeamFor(TokenBasedRememberMeService{}.New())
		AddBeamFor(userDetailsAuthenticationProvider)
		AddBeamFor(DefaultPasswordEncoder)
		GetContainer().EnableScanning()
	})
	Context("with FormLogin", func() {
		BeforeEach(func() {
			httpSecurity := (&HttpSecurityBuilder{}).
				AuthorizedHTTPRequests().
				MatchRequest().Paths("/admin", "/admin/**").HasRole("ADMIN").
				// MatchRequest().Paths("/*").PermitAll().
				And().
				AnyRequest().PermitAll().
				FormLogin().And().
				RememberMe().Key("secret").And().
				Build()
			AddBeamFor(httpSecurity)
			Expect(GetContainer().Initialize()).NotTo(HaveOccurred())
		})

		It("can be created with formLogin", func() {
			chain := GetBeamDefaultInstance[*DefaultSecurityFilterChain]()
			Expect(chain).NotTo(BeNil())
			app := NewMockSecurityAppHandler()
			chain.Initialize("primary", app)
			u := ValErr(url.Parse("http://www.example.com/login"))
			err := Try(
				func() {
					handler := NewMockSecurityHandler(HttpMethods.POST, u)
					handler.SetFormValue("remember-me", "true")
					RaiseErr(app.Execute(handler))
				},
				Catch(func(e SecurityFilterChainException) Error {
					Expect(e.Action()).To(Equal(SecurityFilterAction{}.New().RENDER))
					return e
				}),
			)
			Expect(err).To(HaveOccurred())
		})
		It("can accept authorization request with a redirect", func() {
			chain := GetBeamDefaultInstance[*DefaultSecurityFilterChain]()
			Expect(chain).NotTo(BeNil())
			app := NewMockSecurityAppHandler()
			chain.Initialize("primary", app)

			ex := Try(
				func() {
					handler := NewMockSecurityHandler(HttpMethods.POST, ValErr(url.Parse("http://www.example.com/admin")))
					RaiseErr(app.Execute(handler))
				},
				Catch(func(e SecurityFilterChainException) Error {
					Expect(e.Action()).To(Equal(SecurityFilterAction{}.New().REDIRECT))
					Expect(e.To()).To(Equal("/login"))
					return e
				}),
			)
			Expect(ex).To(HaveOccurred())

			ex = Try(
				func() {
					handler := NewMockSecurityHandler(HttpMethods.GET, ValErr(url.Parse("http://www.example.com/login")))
					RaiseErr(app.Execute(handler))
				},
				Catch(func(e SecurityFilterChainException) Error {
					Expect(e.Action()).To(Equal(SecurityFilterAction{}.New().RENDER))
					return e
				}),
			)
			Expect(ex).To(HaveOccurred())

			ex = Try(
				func() {
					handler := NewMockSecurityHandler(HttpMethods.POST, ValErr(url.Parse("http://www.example.com/login")))
					handler.SetFormValue("username", "admin")
					handler.SetFormValue("password", "bad")
					RaiseErr(app.Execute(handler))
				},
				Catch(func(e SecurityFilterChainException) Error {
					Expect(e.Action()).To(Equal(SecurityFilterAction{}.New().RENDER))
					return e
				}),
			)
			Expect(ex).To(HaveOccurred())

			ex = Try(
				func() {
					handler := NewMockSecurityHandler(HttpMethods.POST, ValErr(url.Parse("http://www.example.com/login")))
					handler.SetFormValue("username", "admin")
					handler.SetFormValue("password", "admin")
					handler.SetSessionValue("redirect", "/admin")
					RaiseErr(app.Execute(handler))
				},
				Catch(func(e SecurityFilterChainException) Error {
					Expect(e.Action()).To(Equal(SecurityFilterAction{}.New().REDIRECT))
					Expect(e.To()).To(Equal("/admin"))
					return e
				}),
			)
			Expect(ex).To(HaveOccurred())
		})

		It("can accept authorization request with remember-me", func() {
			chain := GetBeamDefaultInstance[*DefaultSecurityFilterChain]()
			Expect(chain).NotTo(BeNil())
			app := NewMockSecurityAppHandler()
			chain.Initialize("primary", app)

			handler := NewMockSecurityHandler(HttpMethods.POST, ValErr(url.Parse("http://www.example.com/login")))
			handler.SetFormValue("remember-me", "true")
			handler.SetFormValue("username", "admin")
			handler.SetFormValue("password", "admin")
			handler.SetSessionValue("redirect", "/admin")
			ex := Try(
				func() {
					RaiseErr(app.Execute(handler))
				},
				Catch(func(e SecurityFilterChainException) Error {
					Expect(e.Action()).To(Equal(SecurityFilterAction{}.New().REDIRECT))
					Expect(e.To()).To(Equal("/admin"))
					return e
				}),
			)
			Expect(ex).To(HaveOccurred())

			handler.SetMethod(HttpMethods.GET)
			handler.SetURL(ValErr(url.Parse("http://www.example.com/admin")))
			ex = Try(
				func() {
					RaiseErr(app.Execute(handler))
				},
			)
			Expect(ex).NotTo(HaveOccurred())

			handler.SessionReset()
			ex = Try(
				func() {
					RaiseErr(app.Execute(handler))
				},
			)
			Expect(ex).NotTo(HaveOccurred())

			handler.SetURL(ValErr(url.Parse("http://www.example.com/logout")))
			ex = Try(
				func() {
					RaiseErr(app.Execute(handler))
				},
				Catch(func(e SecurityFilterChainException) Error {
					Expect(e.Action()).To(Equal(SecurityFilterAction{}.New().REDIRECT))
					Expect(e.To()).To(Equal("/"))
					return e
				}),
			)
			Expect(ex).To(HaveOccurred())
		})
	})

	Context("with BasicLogin", func() {
		BeforeEach(func() {
			httpSecurity := (&HttpSecurityBuilder{}).
				Match("/api/**", "/admin", "/admin/**").
				AuthorizedHTTPRequests().
				MatchRequest().Paths("/admin", "/admin/**").HasRole("ADMIN").
				And().
				AnyRequest().HasRole("ADMIN").
				Basic().
				Build()
			AddBeamFor(httpSecurity)
			Expect(GetContainer().Initialize()).NotTo(HaveOccurred())
		})
		It("can accept authorization from basic auth", func() {
			chain := GetBeamDefaultInstance[*DefaultSecurityFilterChain]()
			Expect(chain).NotTo(BeNil())
			app := NewMockSecurityAppHandler()
			chain.Initialize("primary", app)

			base64encode := func(src string) string {
				return base64.StdEncoding.EncodeToString([]byte(src))
			}

			ex := Try(
				func() {
					handler := NewMockSecurityHandler(HttpMethods.GET, ValErr(url.Parse("http://www.example.com/admin")))
					RaiseErr(app.Execute(handler))
				},
				Catch(func(e SecurityFilterChainException) Error {
					Expect(e.Action()).To(Equal(SecurityFilterAction{}.New().STATUS))
					return e
				}),
			)
			Expect(ex).To(HaveOccurred())

			ex = Try(
				func() {
					handler := NewMockSecurityHandler(HttpMethods.GET, ValErr(url.Parse("http://www.example.com/admin")))
					handler.SetHeader("Authorization", "Auth "+base64encode("admin:admin"))
					RaiseErr(app.Execute(handler))
				},
			)
			Expect(ex).To(HaveOccurred())

			ex = Try(
				func() {
					handler := NewMockSecurityHandler(HttpMethods.GET, ValErr(url.Parse("http://www.example.com/admin")))
					handler.SetHeader("Authorization", "Basic admin:admin")
					RaiseErr(app.Execute(handler))
				},
			)
			Expect(ex).To(HaveOccurred())

			ex = Try(
				func() {
					handler := NewMockSecurityHandler(HttpMethods.GET, ValErr(url.Parse("http://www.example.com/admin")))
					handler.SetHeader("Authorization", "Basic "+base64encode("adminadmin"))
					RaiseErr(app.Execute(handler))
				},
			)
			Expect(ex).To(HaveOccurred())

			ex = Try(
				func() {
					handler := NewMockSecurityHandler(HttpMethods.GET, ValErr(url.Parse("http://www.example.com/admin")))
					handler.SetHeader("Authorization", "Basic "+base64encode("admin:user"))
					RaiseErr(app.Execute(handler))
				},
			)
			Expect(ex).To(HaveOccurred())

			ex = Try(
				func() {
					handler := NewMockSecurityHandler(HttpMethods.GET, ValErr(url.Parse("http://www.example.com/admin")))
					handler.SetHeader("Authorization", "Basic "+base64encode("user:user"))
					RaiseErr(app.Execute(handler))
				},
			)
			Expect(ex).To(HaveOccurred())

			ex = Try(
				func() {
					handler := NewMockSecurityHandler(HttpMethods.GET, ValErr(url.Parse("http://www.example.com/api/user")))
					handler.SetHeader("Authorization", "Basic "+base64encode("user:user"))
					RaiseErr(app.Execute(handler))
				},
			)
			Expect(ex).To(HaveOccurred())

			ex = Try(
				func() {
					handler := NewMockSecurityHandler(HttpMethods.GET, ValErr(url.Parse("http://www.example.com/admin")))
					handler.SetHeader("Authorization", "Basic "+base64encode("admin:admin"))
					RaiseErr(app.Execute(handler))
				},
			)
			Expect(ex).NotTo(HaveOccurred())
		})
	})

	Context("With a MessageSourceValidator", func() {
		BeforeEach(func() {
			httpSecurity := (&HttpSecurityBuilder{}).
				AuthorizedHTTPRequests().
				MatchRequest().Paths("/admin", "/admin/**").HasRole("ADMIN").
				// MatchRequest().Paths("/*").PermitAll().
				And().
				AnyRequest().PermitAll().
				FormLogin().And().
				RememberMe().Key("secret").And().
				Build()
			AddBeamFor(httpSecurity)

			defaultLocale := Locales.EN
			localeContextHolder := LocaleContextHolder{}.New(defaultLocale)
			messageSource := MessageSource{}.New(defaultLocale)
			messageSourceValidator := MessageSourceValidator{}.New(localeContextHolder, messageSource)
			bundle := messageSource.DefaultMessageBundle()
			Expect(bundle.AddValidationTranslation(en.RegisterDefaultTranslations)).NotTo(HaveOccurred())
			translations := map[string]string{
				"fields.login.username": "Username",
				"fields.login.password": "Password",
			}
			for k, v := range translations {
				bundle.AddTranslation(k, v)
			}
			AddBeamFor(localeContextHolder)
			AddBeamFor(messageSource)
			AddBeamFor(messageSourceValidator)
			Expect(GetContainer().Initialize()).NotTo(HaveOccurred())
		})
		It("can use a MessageSourceValidator", func() {
			chain := GetBeamDefaultInstance[*DefaultSecurityFilterChain]()
			Expect(chain).NotTo(BeNil())
			app := NewMockSecurityAppHandler()
			chain.Initialize("primary", app)
			ex := Try(
				func() {
					handler := NewMockSecurityHandler(HttpMethods.POST, ValErr(url.Parse("http://www.example.com/login")))
					handler.SetFormValue("username", "admin")
					// handler.SetFormValue("password", "bad")
					RaiseErr(app.Execute(handler))
				},
				Catch(func(e SecurityFilterChainException) Error {
					Expect(e.Action()).To(Equal(SecurityFilterAction{}.New().RENDER))
					return e
				}),
			)
			Expect(ex).To(HaveOccurred())
		})
	})
})
