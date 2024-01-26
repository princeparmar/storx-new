package consoleapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"go.uber.org/atomic"
	"go.uber.org/zap"
)

const (
	zoho_DefaultLeadSource = "register"
	zoho_RefreshTokenFreq  = 45 * time.Minute

	zoho_RefreshTokenURL = "https://accounts.zoho.in/oauth/v2/token"
	zoho_GrantType       = "refresh_token"
)

var token atomic.String

func ZohoRefreshTokenInit(ctx context.Context, clientID, clientSecret, refreshToken string, log *zap.Logger) {
	log = log.Named("zoho_refresh_token")

	if clientID == "" || clientSecret == "" || refreshToken == "" {
		log.Warn("zohoRefreshTokenInit: missing clientID, clientSecret or refreshToken")
		return
	}

	for {
		log.Debug("zohoRefreshToken started")
		err := zohoRefreshToken(ctx, clientID, clientSecret, refreshToken)
		if err != nil {
			log.Error("zohoRefreshToken", zap.Error(err))
			time.Sleep(time.Second)
			continue
		}

		log.Debug("zohoRefreshToken success")

		time.Sleep(zoho_RefreshTokenFreq)
	}
}

func zohoRefreshToken(ctx context.Context, clientID, clientSecret, refreshToken string) (err error) {
	defer func() {
		if r := recover(); r != nil {
			switch r := r.(type) {
			case error:
				err = r
			default:
				err = fmt.Errorf("%v", r)
			}
		}
	}()

	client := &http.Client{}

	req, err := http.NewRequest(http.MethodPost, zoho_RefreshTokenURL, nil)
	if err != nil {
		return err
	}

	q := req.URL.Query()
	q.Add("refresh_token", refreshToken)
	q.Add("client_id", clientID)
	q.Add("client_secret", clientSecret)
	q.Add("grant_type", zoho_GrantType)
	req.URL.RawQuery = q.Encode()

	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	type zohoRefreshTokenResponse struct {
		AccessToken string `json:"access_token"`
		APIDomain   string `json:"api_domain"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}

	response := &zohoRefreshTokenResponse{}
	err = json.NewDecoder(resp.Body).Decode(response)
	if err != nil {
		return err
	}

	// storing access token in atomic.String for thread safety
	token.Store(response.AccessToken)

	return nil
}

func zohoInsertLead(ctx context.Context, fullname, email string, log *zap.Logger) {
	defer func() {
		if r := recover(); r != nil {
			log.Error("zohoInsertLead: panic", zap.Any("panic", r))
		}
	}()

	if token.String() == "" {
		log.Warn("zohoInsertLead: token is empty, skipping")
		return
	}

	names := strings.Split(fullname, " ")
	firstname := names[0]
	lastname := "lastname_not_found"
	if len(names) > 1 {
		lastname = names[1]
	}

	log.Info("zohoInsertLead", zap.String("firstname", firstname), zap.String("lastname", lastname), zap.String("email", email))

	type zohoLeadInsertData struct {
		LeadSource string `json:"Lead_Source"`
		LastName   string `json:"Last_Name"`
		FirstName  string `json:"First_Name"`
		Email      string `json:"Email"`
	}

	type zohoLeadInsertRequest struct {
		Data []zohoLeadInsertData `json:"data"`
	}

	reqBody := &zohoLeadInsertRequest{
		Data: []zohoLeadInsertData{
			{
				LeadSource: zoho_DefaultLeadSource,
				LastName:   lastname,
				FirstName:  firstname,
				Email:      email,
			},
		},
	}

	b, err := json.Marshal(reqBody)
	if err != nil {
		log.Error("zohoInsertLead: json.Marshal", zap.Error(err))
		return
	}

	client := &http.Client{}

	req, err := http.NewRequest(http.MethodPost, "https://www.zohoapis.in/crm/v2/Leads", bytes.NewReader(b))
	if err != nil {
		log.Error("zohoInsertLead: http.NewRequest", zap.Error(err))
		return
	}

	req.Header.Add("Authorization", "Bearer "+token.String())

	resp, err := client.Do(req)
	if err != nil {
		log.Error("zohoInsertLead: client.Do", zap.Error(err))
		return
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Error("zohoInsertLead: io.ReadAll", zap.Error(err))
		return
	}

	fmt.Println("zohoInsertLead:", resp.StatusCode, string(data))

	if resp.StatusCode != http.StatusCreated {
		log.Error("zohoInsertLead: resp.StatusCode != http.StatusOK", zap.Int("status", resp.StatusCode))
		return
	}

	log.Info("zohoInsertLead: success")

}
