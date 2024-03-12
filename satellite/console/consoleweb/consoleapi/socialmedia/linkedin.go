package socialmedia

import (
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/linkedin"
)

type LinkedinUserDetails struct {
	Sub        string `json:"sub"`
	Name       string `json:"name"`
	GivenName  string `json:"given_name"`
	FamilyName string `json:"family_name"`
	Picture    string `json:"picture"`
	// Locale     string `json:"locale"`
	Email string `json:"email"`
	// EmailVerified bool   `json:"email_verified"`
}

// **** LinkedIn ****//
func GetLinkedinOAuthConfig_Register() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     configVal.LinkedinClientID,
		ClientSecret: configVal.LinkedinClientSecret,
		RedirectURL:  configVal.LinkedinOAuthRedirectUrl_register,
		Endpoint:     linkedin.Endpoint,
		Scopes:       []string{"openid", "profile", "email"},
	}
}
func GetLinkedinOAuthConfig_Login() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     configVal.LinkedinClientID,
		ClientSecret: configVal.LinkedinClientSecret,
		RedirectURL:  configVal.LinkedinOAuthRedirectUrl_login,
		Endpoint:     linkedin.Endpoint,
		Scopes:       []string{"openid", "profile", "email"},
	}
}
