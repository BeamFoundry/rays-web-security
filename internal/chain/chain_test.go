package chain_test

import (
	"encoding/base64"
	"net/url"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	. "github.com/BeamFoundry/rays/pkg/core"
	. "github.com/BeamFoundry/rays/pkg/i18n"
	. "github.com/BeamFoundry/rays/pkg/i18n/locales"
	. "github.com/BeamFoundry/rays/pkg/lang"
	. "github.com/BeamFoundry/rays/pkg/testing"
	. "github.com/BeamFoundry/rays/pkg/web"

	_ "github.com/BeamFoundry/rays-web-security/internal/autoconfig"
	. "github.com/BeamFoundry/rays-web-security/internal/chain"

	. "github.com/BeamFoundry/rays-web-security/pkg/config"
	. "github.com/BeamFoundry/rays-web-security/pkg/core"
	. "github.com/BeamFoundry/rays-web-security/pkg/rememberme"
	. "github.com/BeamFoundry/rays-web-security/pkg/testing"
)

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
) RememberMeService {
	return TokenBasedRememberMeService{}.New("secret", that.userDetailsService)
}

type HttpSecurityConfiguration struct {
	Configuration
	rememberMe          RememberMeService    `@:"Inject"`
	httpSecurityBuilder *HttpSecurityBuilder `@:"Inject"`
}

func (this *HttpSecurityConfiguration) HttpSecurity() *HttpSecurity {
	return this.httpSecurityBuilder.RememberMe(this.rememberMe).Build()
}

type SecurityFilterConfiguration struct {
	filters []SecurityFilter `@:"Inject"`
}

func (this *SecurityFilterConfiguration) PostConstruct() Error {
	Expect(this.filters).To(BeEmpty())
	return nil
}

var _ = Describe("SecurityFilterChain", func() {
	BeforeEach(func() {
		AddBeamFor(&UserDetailsServiceConfiguration{})
		GetContainer().EnableScanning()
	})

	Context("With a HttpSecurity", func() {
		BeforeEach(func() {
			httpSecurity := (&HttpSecurityBuilder{}).
				AuthorizedHTTPRequests().
				Paths("/admin", "/admin/**").HasRole("ADMIN").
				And().
				AnyRequest().PermitAll().
				FormLogin().And().
				SessionCreationPolicy().Always()
			AddBeamFor(httpSecurity)
			AddBeamFor(&HttpSecurityConfiguration{})
			AddBeamFor(&SecurityFilterConfiguration{})
			Expect(GetContainer().Initialize()).NotTo(HaveOccurred())
		})

		It("can check if it's enabled", func() {
			chain := GetBeamDefaultInstance[SecurityFilterChain]()
			Expect(chain).NotTo(BeNil())
		})

		It("can obtain a default HttpPolicy", func() {
			chain := GetBeamDefaultInstance[SecurityFilterChain]()
			Expect(chain).NotTo(BeNil())
			app := NewMockSecurityAppHandler()
			chain.Initialize("primary", app)
			u := ValErr(url.Parse("http://www.example.com/index.html"))
			handler := NewMockSecurityHandler(HttpMethods.GET, u)
			Expect(app.Execute(handler)).NotTo(HaveOccurred())
		})
	})
	Context("Without a HttpSecurity", func() {
		BeforeEach(func() {
			/*
				httpSecurity := (&HttpSecurityBuilder{}).
					AnyRequest().PermitAll().
					Build()
				AddBeamFor(httpSecurity)
			*/
			Expect(GetContainer().Initialize()).NotTo(HaveOccurred())
		})
		It("can set up a default HttpSecurity", func() {
			chain := GetBeamDefaultInstance[SecurityFilterChain]()
			Expect(chain).NotTo(BeNil())
			app := NewMockSecurityAppHandler()
			chain.Initialize("primary", app)
			u := ValErr(url.Parse("http://www.example.com/index.html"))
			handler := NewMockSecurityHandler(HttpMethods.GET, u)
			Expect(app.Execute(handler)).NotTo(HaveOccurred())
		})
		It("can get the HTTPPolicyDebugValue", func() {
			chain := GetBeamDefaultInstance[SecurityFilterChain]()
			Expect(chain).NotTo(BeNil())
			app := NewMockSecurityAppHandler()
			app.Get("/index.html", func(_ SecurityHandler) error {
				holder := GetBeamDefaultInstance[SecurityContextHolder]()
				Expect(holder).NotTo(BeNil())
				Expect(holder.GetContext()).NotTo(BeNil())
				Expect(holder.GetContext().GetHTTPPolicyDebugValue()).NotTo(BeEmpty())
				return nil
			})
			chain.Initialize("primary", app)
			u := ValErr(url.Parse("http://www.example.com/index.html"))
			handler := NewMockSecurityHandler(HttpMethods.GET, u)
			Expect(app.Execute(handler)).NotTo(HaveOccurred())
		})
	})

	Context("with FormLogin", func() {
		BeforeEach(func() {
			httpSecurity := (&HttpSecurityBuilder{}).
				AuthorizedHTTPRequests().
				Paths("/admin", "/admin/**").HasRole("ADMIN").
				And().
				AnyRequest().PermitAll().
				FormLogin().And()
			AddBeamFor(httpSecurity)
			AddBeamFor(&HttpSecurityConfiguration{})
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
					Expect(e.Action()).To(Equal(DefaultSecurityFilterAction{}.New().RENDER.Name()))
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
					ex, ok := e.(*DefaultSecurityFilterChainException)
					Expect(ok).To(BeTrue())
					Expect(ex.Action()).To(Equal(DefaultSecurityFilterAction{}.New().REDIRECT.Name()))
					Expect(ex.To()).To(Equal("/login"))
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
					Expect(e.Action()).To(Equal(DefaultSecurityFilterAction{}.New().RENDER.Name()))
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
					Expect(e.Action()).To(Equal(DefaultSecurityFilterAction{}.New().RENDER.Name()))
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
					ex, ok := e.(*DefaultSecurityFilterChainException)
					Expect(ok).To(BeTrue())
					Expect(ex.Action()).To(Equal(DefaultSecurityFilterAction{}.New().REDIRECT.Name()))
					Expect(ex.To()).To(Equal("/admin"))
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
					ex, ok := e.(*DefaultSecurityFilterChainException)
					Expect(ok).To(BeTrue())
					Expect(ex.Action()).To(Equal(DefaultSecurityFilterAction{}.New().REDIRECT.Name()))
					Expect(ex.To()).To(Equal("/admin"))
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
					ex, ok := e.(*DefaultSecurityFilterChainException)
					Expect(ok).To(BeTrue())
					Expect(ex.Action()).To(Equal(DefaultSecurityFilterAction{}.New().REDIRECT.Name()))
					Expect(ex.To()).To(Equal("/"))
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
				Paths("/admin", "/admin/**").HasRole("ADMIN").
				And().
				AnyRequest().HasRole("ADMIN").
				Basic().SessionCreationPolicy().Never().
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
					Expect(e.Action()).To(Equal(DefaultSecurityFilterAction{}.New().ERROR.Name()))
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
	Context("with BasicLogin Stateless", func() {
		BeforeEach(func() {
			httpSecurity := (&HttpSecurityBuilder{}).
				Match("/api/**", "/admin", "/admin/**").
				AuthorizedHTTPRequests().
				Paths("/admin", "/admin/**").HasRole("ADMIN").
				And().
				AnyRequest().HasRole("ADMIN").
				Basic().SessionCreationPolicy().Stateless().
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
				Paths("/admin", "/admin/**").HasRole("ADMIN").
				// Paths("/*").PermitAll().
				And().
				AnyRequest().PermitAll().
				FormLogin().And().Build()
			AddBeamFor(httpSecurity)

			defaultLocale := Locales.EN
			localeContextHolder := DefaultLocaleContextHolder{}.New(defaultLocale)
			messageSource := DefaultMessageSource{}.New(defaultLocale)
			messageSourceValidator := DefaultMessageSourceValidator{}.New(localeContextHolder, messageSource)
			bundle := messageSource.DefaultMessageBundle()
			Expect(bundle.LoadValidationTranslation(ValidationTranslations.EN)).NotTo(HaveOccurred())
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
					Expect(e.Action()).To(Equal(DefaultSecurityFilterAction{}.New().RENDER.Name()))
					return e
				}),
			)
			Expect(ex).To(HaveOccurred())
		})
	})
})
