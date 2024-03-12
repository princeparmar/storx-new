package socialmedia

import (
	"encoding/json"
	"errors"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/facebook"
)

// FacebookUserDetails is struct used for user details
type FacebookUserDetails struct {
	ID    string
	Name  string
	Email string
}

// **** Facebook ****//
func GetFacebookOAuthConfig_Register() *oauth2.Config {

	return &oauth2.Config{
		ClientID:     configVal.FacebookClientID,
		ClientSecret: configVal.FacebookClientSecret,
		RedirectURL:  configVal.FacebookOAuthRedirectUrl_register,
		Endpoint:     facebook.Endpoint,
		Scopes:       []string{"email"},
	}
}
func GetFacebookOAuthConfig_Login() *oauth2.Config {

	return &oauth2.Config{
		ClientID:     configVal.FacebookClientID,
		ClientSecret: configVal.FacebookClientSecret,
		RedirectURL:  configVal.FacebookOAuthRedirectUrl_login,
		Endpoint:     facebook.Endpoint,
		Scopes:       []string{"email"},
	}
}

func GetRandomOAuthStateString() string {
	return "SomeRandomStringAlgorithmForMoreSecurity"
}

func GetUserInfoFromFacebook(token string) (FacebookUserDetails, error) {
	if token == "" {
		return FacebookUserDetails{}, errors.New("invalid facebook client id or secret")
	}

	var fbUserDetails FacebookUserDetails
	facebookUserDetailsRequest, _ := http.NewRequest("GET", "https://graph.facebook.com/me?fields=id,name,email&access_token="+token, nil)
	facebookUserDetailsResponse, facebookUserDetailsResponseError := http.DefaultClient.Do(facebookUserDetailsRequest)

	if facebookUserDetailsResponseError != nil {
		return FacebookUserDetails{}, errors.New("error occurred while getting information from Facebook")
	}

	decoder := json.NewDecoder(facebookUserDetailsResponse.Body)
	decoderErr := decoder.Decode(&fbUserDetails)
	defer facebookUserDetailsResponse.Body.Close()

	if decoderErr != nil {
		return FacebookUserDetails{}, errors.New("error occurred while getting information from Facebook")
	}

	return fbUserDetails, nil
}
