package rememberme_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	. "github.com/BeamFoundry/rays/pkg/core"
	. "github.com/BeamFoundry/rays/pkg/lang"
	. "github.com/BeamFoundry/rays/pkg/testing"
	. "github.com/BeamFoundry/rays/pkg/web"

	_ "github.com/BeamFoundry/rays-web-security/internal/autoconfig"

	. "github.com/BeamFoundry/rays-web-security/pkg/config"
	. "github.com/BeamFoundry/rays-web-security/pkg/core"
	. "github.com/BeamFoundry/rays-web-security/pkg/rememberme"
	. "github.com/BeamFoundry/rays-web-security/pkg/testing"
)

func TestRememberme(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Rememberme Suite")
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
	return TokenBasedRememberMeService{}.New("secret", that.userDetailsService).
		WithParameter("remember-me").
		WithCookieDomain("").
		WithCookieName("remember-me").
		WithCookieSecure(true).
		WithValidity(1209600)
}

type HttpSecurityConfiguration struct {
	Configuration
	rememberMe   RememberMeService    `@:"Inject"`
	httpSecurity *HttpSecurityBuilder `@:"Inject"`
}

func (this *HttpSecurityConfiguration) HttpSecurity() *HttpSecurity {
	return this.httpSecurity.RememberMe(this.rememberMe).Build()
}

func base64encode(src string) string {
	return base64.StdEncoding.EncodeToString([]byte(src))
}

var _ = Describe("TokenBasedRememberMeService", func() {
	var chain SecurityFilterChain
	var app *MockSecurityAppHandler
	var remember *TokenBasedRememberMeService
	BeforeEach(func() {
		httpSecurity := (&HttpSecurityBuilder{}).
			AuthorizedHTTPRequests().
			Paths("/admin", "/admin/**").HasRole("ADMIN").
			Paths("/*").PermitAll().
			And().
			AnyRequest().DenyAll().
			FormLogin().And()
		AddBeamFor(httpSecurity)
		AddBeamFor(&UserDetailsServiceConfiguration{})
		AddBeamFor(&HttpSecurityConfiguration{})
		GetContainer().EnableScanning()
		Expect(GetContainer().Initialize()).NotTo(HaveOccurred())

		chain = GetBeamDefaultInstance[SecurityFilterChain]()
		Expect(chain).NotTo(BeNil())
		app = NewMockSecurityAppHandler()
		remember = GetBeamDefaultInstance[*TokenBasedRememberMeService]()
		Expect(remember.Parameter()).NotTo(BeEmpty())
		/*
			Expect(remember.CookieDomain()).To(BeEmpty())
			Expect(remember.CookieName()).NotTo(BeEmpty())
			Expect(remember.CookieSecure()).To(BeFalse())
			Expect(remember.Validity()).To(Equal(1209600))
		*/
		chain.Initialize("primary", app)
	})
	Context("With a blank handler", func() {
		It("can be used", func() {
			ex := Try(
				func() {
					handler := NewMockSecurityHandler(HttpMethods.POST, ValErr(url.Parse("http://www.example.com/admin")))
					handler.SetFormValue("remember-me", "true")
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
		})
	})
	Context("With a reusable handler", func() {
		var handler *MockSecurityHandler
		It("Will login eventually", func() {
			// BeforeAll(func() {
			handler = NewMockSecurityHandler(HttpMethods.POST, ValErr(url.Parse("http://www.example.com/login")))
			handler.SetFormValue("username", "admin")
			handler.SetFormValue("password", "bad")
			ex := Try(
				func() {
					RaiseErr(app.Execute(handler))
				},
				Catch(func(e SecurityFilterChainException) Error {
					Expect(e.Action()).To(Equal(DefaultSecurityFilterAction{}.New().RENDER.Name()))
					return e
				}),
			)
			Expect(ex).To(HaveOccurred())
			remember.Logout(handler)
			// })
			// It("can login with an invalid cookie", func() {
			handler.SetFormValue("password", "admin")
			handler.SetFormValue("remember-me", "")
			handler.SetSessionValue("redirect", "/admin")
			c := &http.Cookie{
				Name:     remember.CookieName(),
				Value:    "",
				Domain:   remember.CookieDomain(),
				Expires:  time.Now().Add(time.Second * time.Duration(remember.Validity())),
				SameSite: http.SameSiteStrictMode,
				Secure:   remember.CookieSecure(),
			}
			handler.SetCookie(c)
			ex = Try(
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
			// })
			// It("can login and obtain a rememberme cookie", func() {
			handler.SessionReset()
			handler.SetSessionValue("redirect", "/admin")
			handler.SetFormValue("remember-me", "true")

			ex = Try(
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
			handler.SessionReset()
			handler.SetFormValue("password", "")
			handler.SetURL(ValErr(url.Parse("http://www.example.com/admin")))

			ex = Try(
				func() {
					RaiseErr(app.Execute(handler))
				},
			)
			Expect(ex).NotTo(HaveOccurred())
			remember.Logout(handler)
			// })
		})
	})
	Context("With a reusable handler and cookie", func() {
		var handler *MockSecurityHandler
		var cookie *http.Cookie
		var cookie_value string
		BeforeEach(func() {
			handler = NewMockSecurityHandler(HttpMethods.POST, ValErr(url.Parse("http://www.example.com/login")))
			handler.SetFormValue("username", "admin")
			handler.SetFormValue("password", "admin")
			handler.SetFormValue("remember-me", "true")
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
			cookie = ValErr(handler.Cookie("remember-me"))
			cookie_value = cookie.Value
		})
		It("will fail on invalid cookie value", func() {
			handler.SessionReset()
			cookie.Value = "AAA=A"
			ex := Try(
				func() {
					RaiseErr(app.Execute(handler))
				},
			)
			Expect(ex).To(HaveOccurred())
		})
		It("will fail on invalid cookie value", func() {
			handler.SessionReset()
			cookie.Value = base64encode("admin:admin")
			ex := Try(
				func() {
					RaiseErr(app.Execute(handler))
				},
			)
			Expect(ex).To(HaveOccurred())
		})
		It("will fail on invalid cookie value", func() {
			handler.SessionReset()
			cookie.Value = base64encode("nobody:-:-:-")
			ex := Try(
				func() {
					RaiseErr(app.Execute(handler))
				},
			)
			Expect(ex).To(HaveOccurred())
		})
		It("will fail on invalid cookie value", func() {
			handler.SessionReset()
			cb, err := base64.StdEncoding.DecodeString(cookie_value)
			Expect(err).NotTo(HaveOccurred())
			elements := strings.Split(string(cb), ":")
			elements[3] = "-"
			cookie.Value = base64encode(strings.Join(elements, ":"))
			ex := Try(
				func() {
					RaiseErr(app.Execute(handler))
				},
			)
			Expect(ex).To(HaveOccurred())
		})
		It("will fail on invalid cookie value", func() {
			userDetailsService := GetBeamDefaultInstance[UserDetailsService]()
			handler.SessionReset()
			var buffer bytes.Buffer
			expires := time.Now().Truncate(time.Second * time.Duration(remember.Validity()))
			expires_milli := strconv.FormatInt(expires.UnixMilli(), 10)
			fmt.Fprintf(&buffer, "%s:%s:SHA256", "admin", expires_milli)
			buffer.WriteRune(':')
			password := userDetailsService.LoadUserByUsername("admin").GetPassword()
			hash := sha256.Sum256(fmt.Appendf(nil, "%s:%s:%s:%s", "admin", expires_milli, password, remember.Key()))
			fmt.Fprintf(&buffer, "%x", hash[:])

			cookie.Value = base64encode(buffer.String())
			ex := Try(
				func() {
					RaiseErr(app.Execute(handler))
				},
			)
			Expect(ex).To(HaveOccurred())
		})
		It("will fail on invalid cookie value", func() {
			userDetailsService := GetBeamDefaultInstance[UserDetailsService]()
			handler.SessionReset()
			var buffer bytes.Buffer
			fmt.Fprintf(&buffer, "%s:%s:SHA256", "admin", "admin")
			buffer.WriteRune(':')
			password := userDetailsService.LoadUserByUsername("admin").GetPassword()
			hash := sha256.Sum256(fmt.Appendf(nil, "%s:%s:%s:%s", "admin", "admin", password, remember.Key()))
			fmt.Fprintf(&buffer, "%x", hash[:])

			cookie.Value = base64encode(buffer.String())
			ex := Try(
				func() {
					RaiseErr(app.Execute(handler))
				},
			)
			Expect(ex).To(HaveOccurred())
		})
	})
})
