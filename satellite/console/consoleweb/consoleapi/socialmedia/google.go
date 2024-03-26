package socialmedia

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

type GoogleOauthToken struct {
	Access_token string
	Id_token     string
}
type GoogleUserResult struct {
	Id             string
	Email          string
	Verified_email bool
	Name           string
	Given_name     string
	Family_name    string
	Picture        string
	Locale         string
}

func GetGoogleOauthToken(code string, mode string) (*GoogleOauthToken, error) {

	if mode != "signup" && mode != "signin" {
		return nil, errors.New("invalid mode")
	}

	if configVal.GoogleClientID == "" || configVal.GoogleClientSecret == "" {
		return nil, errors.New("invalid google client id or secret")
	}

	const rootURl = "https://oauth2.googleapis.com/token"

	values := url.Values{}
	values.Add("grant_type", "authorization_code")
	values.Add("code", code)
	values.Add("client_id", configVal.GoogleClientID)
	values.Add("client_secret", configVal.GoogleClientSecret)
	if mode == "signup" {
		values.Add("redirect_uri", configVal.GoogleOAuthRedirectUrl_register)
	} else if mode == "signin" {
		values.Add("redirect_uri", configVal.GoogleOAuthRedirectUrl_login)
	}

	query := values.Encode()

	fmt.Println("GOOGLE Query: "+query, "mode: "+mode)

	req, err := http.NewRequest("POST", rootURl, bytes.NewBufferString(query))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := http.Client{
		Timeout: time.Second * 30,
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	if res.StatusCode != http.StatusOK {
		return nil, errors.New("could not retrieve token")
	}

	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	var GoogleOauthTokenRes map[string]interface{}

	if err := json.Unmarshal(resBody, &GoogleOauthTokenRes); err != nil {
		return nil, err
	}

	tokenBody := &GoogleOauthToken{
		Access_token: GoogleOauthTokenRes["access_token"].(string),
		Id_token:     GoogleOauthTokenRes["id_token"].(string),
	}

	return tokenBody, nil
}

func GetGoogleUser(access_token string, id_token string) (*GoogleUserResult, error) {
	if access_token == "" || id_token == "" {
		return nil, errors.New("invalid token")
	}

	if configVal.GoogleClientID == "" || configVal.GoogleClientSecret == "" {
		return nil, errors.New("invalid google client id or secret")
	}

	rootUrl := fmt.Sprintf("https://www.googleapis.com/oauth2/v1/userinfo?alt=json&access_token=%s", access_token)

	req, err := http.NewRequest("GET", rootUrl, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", id_token))

	client := http.Client{
		Timeout: time.Second * 30,
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	if res.StatusCode != http.StatusOK {
		return nil, errors.New("could not retrieve user")
	}

	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	var GoogleUserRes GoogleUserResult

	if err := json.Unmarshal(resBody, &GoogleUserRes); err != nil {
		return nil, err
	}

	userBody := &GoogleUserResult{
		Id:             GoogleUserRes.Id,
		Email:          GoogleUserRes.Email,
		Verified_email: GoogleUserRes.Verified_email,
		Name:           GoogleUserRes.Name,
		Given_name:     GoogleUserRes.Given_name,
		Picture:        GoogleUserRes.Picture,
		Locale:         GoogleUserRes.Locale,
	}

	return userBody, nil
}
