// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package analytics

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/spacemonkeygo/monkit/v3"
	"github.com/zeebo/errs"
	"go.uber.org/zap"

	"storj.io/common/sync2"
)

var mon = monkit.Package()

const (
	eventPrefix      = "pe20293085"
	expiryBufferTime = 5 * time.Minute
	// string template for hubspot submission form. %s is a placeholder for the form(ID) being submitted.
	hubspotFormTemplate = "https://api.hsforms.com/submissions/v3/integration/submit/20293085/%s"
	// This form(ID) is the business account form.
	professionalFormID = "cc693502-9d55-4204-ae61-406a19148cfe"
	// This form(ID) is the personal account form.
	basicFormID = "77cfa709-f533-44b8-bf3a-ed1278ca3202"
	// this form  ID  is the minimal  account form.
	minimalFormID = "926d1b53-f21f-486b-9f15-3b3d341cc4e1"
	// The hubspot lifecycle stage of all new accounts (Product Qualified Lead).
	lifecycleStage = "66198674"
)

// HubSpotConfig is a configuration struct for Concurrent Sending of Events.
type HubSpotConfig struct {
	RefreshToken    string        `help:"hubspot refresh token" default:""`
	TokenAPI        string        `help:"hubspot token refresh API" default:"https://api.hubapi.com/oauth/v1/token"`
	ClientID        string        `help:"hubspot client ID" default:""`
	ClientSecret    string        `help:"hubspot client secret" default:""`
	ChannelSize     int           `help:"the number of events that can be in the queue before dropping" default:"1000"`
	ConcurrentSends int           `help:"the number of concurrent api requests that can be made" default:"4"`
	DefaultTimeout  time.Duration `help:"the default timeout for the hubspot http client" default:"10s"`
}

// HubSpotEvent is a configuration struct for sending API request to HubSpot.
type HubSpotEvent struct {
	Data     map[string]interface{}
	Endpoint string
	Method   *string
}

// HubSpotEvents is a configuration struct for sending Events data to HubSpot.
type HubSpotEvents struct {
	log             *zap.Logger
	config          HubSpotConfig
	events          chan []HubSpotEvent
	refreshToken    string
	tokenAPI        string
	satelliteName   string
	worker          sync2.Limiter
	httpClient      *http.Client
	clientID        string
	clientSecret    string
	accessTokenData *TokenData
	mutex           sync.Mutex
}

// TokenData contains data related to the Hubspot access token.
type TokenData struct {
	AccessToken string
	ExpiresAt   time.Time
}

// NewHubSpotEvents for sending user events to HubSpot.
func NewHubSpotEvents(log *zap.Logger, config HubSpotConfig, satelliteName string) *HubSpotEvents {
	return &HubSpotEvents{
		log:           log,
		config:        config,
		events:        make(chan []HubSpotEvent, config.ChannelSize),
		refreshToken:  config.RefreshToken,
		tokenAPI:      config.TokenAPI,
		clientID:      config.ClientID,
		clientSecret:  config.ClientSecret,
		satelliteName: satelliteName,
		worker:        *sync2.NewLimiter(config.ConcurrentSends),
		httpClient: &http.Client{
			Timeout: config.DefaultTimeout,
		},
	}
}

// Run for concurrent API requests.
func (q *HubSpotEvents) Run(ctx context.Context) error {
	defer q.worker.Wait()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case ev := <-q.events:
			q.worker.Go(ctx, func() {
				err := q.Handle(ctx, ev)
				if err != nil {
					q.log.Error("Sending hubspot event", zap.Error(err))
				}
			})
		}
	}
}

// EnqueueCreateUser for creating user in HubSpot.
func (q *HubSpotEvents) EnqueueCreateUser(fields TrackCreateUserFields) {
	fullName := fields.FullName
	names := strings.SplitN(fullName, " ", 2)

	var firstName string
	var lastName string

	if len(names) > 1 {
		firstName = names[0]
		lastName = names[1]
	} else {
		firstName = fullName
	}

	newField := func(name string, value interface{}) map[string]interface{} {
		return map[string]interface{}{
			"name":  name,
			"value": value,
		}
	}

	formFields := []map[string]interface{}{
		newField("email", fields.Email),
		newField("firstname", firstName),
		newField("lastname", lastName),
		newField("origin_header", fields.OriginHeader),
		newField("signup_referrer", fields.Referrer),
		newField("account_created", "true"),
		newField("have_sales_contact", strconv.FormatBool(fields.HaveSalesContact)),
		newField("signup_partner", fields.UserAgent),
		newField("lifecyclestage", lifecycleStage),
	}
	if fields.SignupCaptcha != nil {
		formFields = append(formFields, newField("signup_captcha_score", *fields.SignupCaptcha))
	}

	properties := map[string]interface{}{
		"userid":             fields.ID.String(),
		"email":              fields.Email,
		"name":               fields.FullName,
		"satellite_selected": q.satelliteName,
		"account_type":       string(fields.Type),
		"company_size":       fields.EmployeeCount,
		"company_name":       fields.CompanyName,
		"job_title":          fields.JobTitle,
	}

	var formURL string

	if fields.Type == Professional {
		formFields = append(formFields, newField("company", fields.CompanyName))
		formFields = append(formFields, newField("storage_needs", fields.StorageNeeds))

		properties["storage_needs"] = fields.StorageNeeds

		formURL = fmt.Sprintf(hubspotFormTemplate, professionalFormID)
	} else {
		formURL = fmt.Sprintf(hubspotFormTemplate, basicFormID)
	}

	data := map[string]interface{}{
		"fields": formFields,
	}

	if fields.HubspotUTK != "" {
		data["context"] = map[string]interface{}{
			"hutk": fields.HubspotUTK,
		}
	}

	createUser := HubSpotEvent{
		Endpoint: formURL,
		Data:     data,
	}

	sendUserEvent := HubSpotEvent{
		Endpoint: "https://api.hubapi.com/events/v3/send",
		Data: map[string]interface{}{
			"email":      fields.Email,
			"eventName":  eventPrefix + "_" + strings.ToLower(q.satelliteName) + "_" + "account_created",
			"properties": properties,
		},
	}
	select {
	case q.events <- []HubSpotEvent{createUser, sendUserEvent}:
	default:
		q.log.Error("create user hubspot event failed, event channel is full")
	}
}

// EnqueueCreateUserMinimal is for creating user in HubSpot using the minimal form.
func (q *HubSpotEvents) EnqueueCreateUserMinimal(fields TrackCreateUserFields) {
	newField := func(name string, value interface{}) map[string]interface{} {
		return map[string]interface{}{
			"name":  name,
			"value": value,
		}
	}

	formFields := []map[string]interface{}{
		newField("email", fields.Email),
		newField("origin_header", fields.OriginHeader),
		newField("signup_referrer", fields.Referrer),
		newField("account_created", "true"),
		newField("signup_partner", fields.UserAgent),
		newField("lifecyclestage", lifecycleStage),
	}
	if fields.SignupCaptcha != nil {
		formFields = append(formFields, newField("signup_captcha_score", *fields.SignupCaptcha))
	}

	properties := map[string]interface{}{
		"userid":             fields.ID.String(),
		"email":              fields.Email,
		"satellite_selected": q.satelliteName,
	}

	formURL := fmt.Sprintf(hubspotFormTemplate, minimalFormID)

	data := map[string]interface{}{
		"fields": formFields,
	}

	if fields.HubspotUTK != "" {
		data["context"] = map[string]interface{}{
			"hutk": fields.HubspotUTK,
		}
	}

	createUser := HubSpotEvent{
		Endpoint: formURL,
		Data:     data,
	}

	sendUserEvent := HubSpotEvent{
		Endpoint: "https://api.hubapi.com/events/v3/send",
		Data: map[string]interface{}{
			"email":      fields.Email,
			"eventName":  eventPrefix + "_" + strings.ToLower(q.satelliteName) + "_" + "account_created",
			"properties": properties,
		},
	}

	select {
	case q.events <- []HubSpotEvent{createUser, sendUserEvent}:
	default:
		q.log.Error("create user hubspot event failed, event channel is full")
	}
}

// EnqueueUserOnboardingInfo is for sending post-creation information to Hubspot, that the user enters after login  during onboarding.
func (q *HubSpotEvents) EnqueueUserOnboardingInfo(fields TrackOnboardingInfoFields) {
	fullName := fields.FullName
	names := strings.SplitN(fullName, " ", 2)

	var firstName string
	var lastName string

	if len(names) > 1 {
		firstName = names[0]
		lastName = names[1]
	} else {
		firstName = fullName
	}

	properties := map[string]interface{}{
		"email":       fields.Email,
		"firstname":   firstName,
		"lastname":    lastName,
		"storage_use": fields.StorageUseCase,
	}
	if fields.Type == Professional {
		properties["have_sales_contact"] = fields.HaveSalesContact
		properties["company_size"] = fields.EmployeeCount
		properties["company"] = fields.CompanyName
		properties["title"] = fields.JobTitle
		properties["storage_needs"] = fields.StorageNeeds
		properties["functional_area"] = fields.FunctionalArea
	}

	updateContactEndpoint := fmt.Sprintf("https://api.hubapi.com/crm/v3/objects/contacts/%s?idProperty=email", url.QueryEscape(fields.Email))
	method := http.MethodPatch

	onboardingInfoEvent := HubSpotEvent{
		Endpoint: updateContactEndpoint,
		Method:   &method,
		Data: map[string]interface{}{
			"properties": properties,
		},
	}

	select {
	case q.events <- []HubSpotEvent{onboardingInfoEvent}:
	default:
		q.log.Error("update user properties hubspot event failed, event channel is full")
	}
}

// handleSingleEvent for handle the single HubSpot API request.
func (q *HubSpotEvents) handleSingleEvent(ctx context.Context, ev HubSpotEvent) (err error) {
	payloadBytes, err := json.Marshal(ev.Data)
	if err != nil {
		return Error.New("json marshal failed: %w", err)
	}

	method := http.MethodPost
	if ev.Method != nil {
		method = *ev.Method
	}
	req, err := http.NewRequestWithContext(ctx, method, ev.Endpoint, bytes.NewReader(payloadBytes))
	if err != nil {
		return Error.New("new request failed: %w", err)
	}

	token, err := q.getAccessToken(ctx)
	if err != nil {
		return Error.New("token request failed: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := q.httpClient.Do(req)
	if err != nil {
		q.log.Error("send request failed", zap.Error(err))
		return Error.New("send request failed: %w", err)
	}

	defer func() {
		err = errs.Combine(err, resp.Body.Close())
	}()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		type hsError struct {
			Message string `json:"message"`
			In      string `json:"in"`
		}
		var data struct {
			Message string    `json:"message"`
			Errors  []hsError `json:"errors"`
		}
		err = json.NewDecoder(resp.Body).Decode(&data)
		if err != nil {
			return Error.New("decoding response failed: %w", err)
		}
		return Error.New("sending event failed: %s - %v", data.Message, data.Errors)
	}
	return err
}

// Handle for handle the HubSpot API requests.
func (q *HubSpotEvents) Handle(ctx context.Context, events []HubSpotEvent) (err error) {
	defer mon.Task()(&ctx)(&err)
	for _, ev := range events {
		err := q.handleSingleEvent(ctx, ev)
		if err != nil {
			return Error.New("handle event: %w", err)
		}
	}
	return nil
}

// getAccessToken returns an access token for hubspot.
// It fetches a new token if there isn't one already or the old one is about to expire in expiryBufferTime.
// It locks q.mutex to ensure only one goroutine is able to request for a token.
func (q *HubSpotEvents) getAccessToken(ctx context.Context) (token string, err error) {
	defer mon.Task()(&ctx)(&err)

	q.mutex.Lock()
	defer q.mutex.Unlock()

	if q.accessTokenData == nil || q.accessTokenData.ExpiresAt.Add(-expiryBufferTime).Before(time.Now()) {
		q.accessTokenData, err = q.getAccessTokenFromHubspot(ctx)
		if err != nil {
			return "", err
		}
	}

	return q.accessTokenData.AccessToken, nil
}

// getAccessTokenFromHubspot gets a new access token from hubspot.
// Expects q.mutex to be locked.
func (q *HubSpotEvents) getAccessTokenFromHubspot(ctx context.Context) (_ *TokenData, err error) {
	defer mon.Task()(&ctx)(&err)

	values := make(url.Values)
	values.Set("grant_type", "refresh_token")
	values.Set("client_id", q.clientID)
	values.Set("client_secret", q.clientSecret)
	values.Set("refresh_token", q.refreshToken)

	encoded := values.Encode()

	buff := bytes.NewBufferString(encoded)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, q.tokenAPI, buff)
	if err != nil {
		return nil, Error.New("new request failed: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := q.httpClient.Do(req)
	if err != nil {
		return nil, Error.New("send request failed: %w", err)
	}
	defer func() {
		err = errs.Combine(err, resp.Body.Close())
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, Error.New("send request failed: %w", err)
	}

	var tokenData struct {
		ExpiresIn   int    `json:"expires_in"`
		AccessToken string `json:"access_token"`
	}
	err = json.NewDecoder(resp.Body).Decode(&tokenData)
	if err != nil {
		return nil, Error.New("decode response failed: %w", err)
	}
	return &TokenData{
		AccessToken: tokenData.AccessToken,
		ExpiresAt:   time.Now().Add(time.Duration(tokenData.ExpiresIn * 1000)),
	}, nil
}
