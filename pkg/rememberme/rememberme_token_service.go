package rememberme

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	. "github.com/BeamFoundry/rays-web-security/pkg/auth"
	. "github.com/BeamFoundry/rays-web-security/pkg/core"

	. "github.com/BeamFoundry/rays/pkg/lang"
)

// TODO: Extract configuration to o dedicated struct
type TokenBasedRememberMeService struct {
	userDetailsService UserDetailsService
	key                string
	parameter          string
	cookieDomain       string
	cookieName         string
	validity           int
	cookieSecure       bool
}

var _ RememberMeService = &TokenBasedRememberMeService{}

// New() returns a new [TokenBasedRememberMeService] with the secret Key 'key', for the specified [userDetailsService].
//
//nolint:gocritic // Constructor
func (this TokenBasedRememberMeService) New(key string, userDetailsService UserDetailsService) *TokenBasedRememberMeService {
	this.key = key
	this.userDetailsService = userDetailsService
	rm := "remember-me"
	this.key = rm
	this.parameter = rm
	this.cookieName = rm
	this.validity = 1209600
	return &this
}

// Key() returns the secret key configured
//
// NOTE: Provided for debugging and testing purpose.
func (this *TokenBasedRememberMeService) Key() string {
	return this.key
}

// WithParameter() let you specify which form input which should be checked to see if the remember-me
// cookie should be created.
//
// Default : "remember-me"
func (this *TokenBasedRememberMeService) WithParameter(parameter string) *TokenBasedRememberMeService {
	this.parameter = parameter
	return this
}

// Parameter() returns the form input which should be checked to see if the remember-me cookie should be
// created.
//
// NOTE: Provided for debugging and testing purpose.
func (this *TokenBasedRememberMeService) Parameter() string {
	return this.parameter
}

// WithCookieDomain() lets you restrict the remember-me cookie domain.
//
// Default: ""
func (this *TokenBasedRememberMeService) WithCookieDomain(cookieDomain string) *TokenBasedRememberMeService {
	this.cookieDomain = cookieDomain
	return this
}

// CookieDomain() lets you retrieve the remember-me cookie domain.
//
// NOTE: Provided for debugging and testing purpose.
func (this *TokenBasedRememberMeService) CookieDomain() string {
	return this.cookieDomain
}

// WithCookieName() lets you set the remember-me cookie name.
//
// Default: "remember-me"
func (this *TokenBasedRememberMeService) WithCookieName(cookieName string) *TokenBasedRememberMeService {
	this.cookieName = cookieName
	return this
}

// CookieName() lets you retrieve the remember-me cookie name.
//
// NOTE: Provided for debugging and testing purpose.
func (this *TokenBasedRememberMeService) CookieName() string {
	return this.cookieName
}

// WithCookieSecure() lets you define if the secure bit on the remember-me cookie should be set.
//
// Default: false
func (this *TokenBasedRememberMeService) WithCookieSecure(cookieSecure bool) *TokenBasedRememberMeService {
	this.cookieSecure = cookieSecure
	return this
}

// CookieSecure() lets you retrieve if the secure bit on the remember-me cookie should be set.
//
// NOTE: Provided for debugging and testing purpose.
func (this *TokenBasedRememberMeService) CookieSecure() bool {
	return this.cookieSecure
}

// WithValidity() lets you specify for how long, in seconds, the remember-me cookie will be valid.
//
// Default: 1209600 seconds (14 days).
func (this *TokenBasedRememberMeService) WithValidity(validity int) *TokenBasedRememberMeService {
	this.validity = validity
	return this
}

// NOTE: Provided for debugging and testing purpose.
func (this *TokenBasedRememberMeService) Validity() int {
	return this.validity
}

// AutoLogin() implements [RememberMeService.AutoLogin].
func (this *TokenBasedRememberMeService) AutoLogin(handler SecurityHandler) (Authentication, Error) {
	cookie, err := handler.Cookie(this.cookieName)
	if err != nil {
		return nil, NewError("CookieError", err.Error())
	}

	cb, err := base64.StdEncoding.DecodeString(cookie.Value)
	if err != nil {
		return nil, NewError("RememberMeError", err.Error())
	}

	elements := strings.Split(string(cb), ":")
	if len(elements) != 4 {
		return nil, NewError("RememberMeError", "Invalid cookie elements", "length", len(elements))
	}

	userDetails := this.userDetailsService.LoadUserByUsername(elements[0])
	if userDetails == nil {
		return nil, NewError("RememberMeError", "UserDetails not found")
	}

	username := userDetails.GetUsername()
	password := userDetails.GetPassword()
	expires := elements[1]
	hash := sha256.Sum256(fmt.Appendf(nil, "%s:%s:%s:%s", username, expires, password, this.key))
	hash_string := hex.EncodeToString(hash[:])
	if hash_string != elements[3] {
		return nil, NewError("RememberMeError", "Hash not corresponding")
	}
	expires_milli, err := strconv.ParseInt(expires, 10, 64)
	if err != nil {
		return nil, NewError("RememberMeError", "Invalid expires data", "expires", expires)
	}
	if time.Now().After(time.UnixMilli(expires_milli)) {
		return nil, NewError("RememberMeError", "RememberMe cookie has expired", "time", time.UnixMilli(expires_milli).Format(time.RFC1123))
	}

	return RememberMeAuthenticationToken{}.New(this.key, userDetails, userDetails.GetAuthorities()), nil
}

// LoginSuccess() implements [RememberMeService.LoginSuccess].
func (this *TokenBasedRememberMeService) LoginSuccess(handler SecurityHandler, successfulAuthentication Authentication) {
	if parameter := handler.FormValue(this.parameter); parameter == "" {
		if cookie, err := handler.Cookie(this.cookieName); err == nil {
			cookie.Value = ""
			cookie.Expires = time.Unix(0, 0)
			handler.SetCookie(cookie)
		}
		return
	}

	if userDetails, ok := successfulAuthentication.GetPrincipal().(UserDetails); ok {
		username := userDetails.GetUsername()
		password := userDetails.GetPassword()
		var buffer bytes.Buffer

		expires := time.Now().Add(time.Second * time.Duration(this.validity))
		expires_milli := strconv.FormatInt(expires.UnixMilli(), 10)
		fmt.Fprintf(&buffer, "%s:%s:SHA256", username, expires_milli)
		buffer.WriteRune(':')
		hash := sha256.Sum256(fmt.Appendf(nil, "%s:%s:%s:%s", username, expires_milli, password, this.key))
		fmt.Fprintf(&buffer, "%x", hash[:])

		encoded := base64.StdEncoding.EncodeToString(buffer.Bytes())
		cookie := &http.Cookie{
			Name:     this.cookieName,
			Value:    encoded,
			Domain:   this.cookieDomain,
			Expires:  expires,
			SameSite: http.SameSiteStrictMode,
			Secure:   this.cookieSecure,
		}

		if domain := this.cookieDomain; domain == "" {
			cookie.Domain = handler.URL().Hostname()
		}

		handler.SetCookie(cookie)
	}
}

// LoginFail() implements [RememberMeService.LoginFail].
//
// TODO: Add implementation
func (this *TokenBasedRememberMeService) LoginFail(_ SecurityHandler) {
}

func (this *TokenBasedRememberMeService) Logout(handler SecurityHandler) {
	cookie, err := handler.Cookie(this.cookieName)
	if err != nil {
		return
	}

	cookie.Value = ""
	cookie.Expires = time.Unix(0, 0)
	handler.SetCookie(cookie)
}
