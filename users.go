package redditgo

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cristalhq/jwt/v5"
)

// var redditOAuthState string
// var redditRedirectUri string
// var redditClientId string
// var redditSecret string
// var redditBasicAuth string
// var RedditAuthUrl string

var client http.Client

type PostBody struct {
	GrantType    string `json:"grant_type"`
	Code         string `json:"code,omitempty"`
	RedirectUri  string `json:"redirect_uri,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

type AccessTokenBody struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	RefreshToken string `json:"refresh_token"`
}

type Clock interface {
	Now() time.Time
}

type RealClock struct{}

func (RealClock) Now() time.Time {
	return time.Now()
}

var clock Clock = RealClock{}

func (atb AccessTokenBody) GetExpireDtTm() time.Time {
	return clock.Now().UTC().Add(time.Second * time.Duration(atb.ExpiresIn))
}

type UserInfo struct {
	Username string `json:"display_name_prefixed"`
	IconImg  string `json:"icon_img"`
}

type UserResponse struct {
	Data UserInfo `json:"subreddit"`
}

const (
	CookieName string = "redditGoCookie"
)

type RedditAuthCaller interface {
	callAccessTokenApi(PostBody) (*http.Response, error)
	callRefreshAccessTokenApi(PostBody) (*http.Response, error)
	getRedditAccessToken(string, string) (*AccessTokenBody, bool)
	refreshRedditAccessToken(*User) (*User, bool)
}

type RealRedditAuthCaller struct {
	envs *ClientEnvs
}

func createUserJwt(username string, jwtSecret string) string {
	key := []byte(jwtSecret)

	signer, err := jwt.NewSignerHS(jwt.HS256, key)
	if err != nil {
		logger.Debug("failed to create jwt signer", "err", err)
	}
	tm := clock.Now().UTC().Add(time.Hour * time.Duration(24))
	claims := &jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(tm),
		Subject:   username,
	}

	builder := jwt.NewBuilder(signer)
	token, err := builder.Build(claims)
	if err != nil {
		logger.Debug("failed to build jwt token", "err", err)
	}

	return token.String()
}

func createUserCookie(userCookie UserCookie, jwtSecret string) http.Cookie {
	jwt := createUserJwt(userCookie.Username, jwtSecret)

	cookie := http.Cookie{
		Name:     CookieName,
		Value:    jwt,
		Path:     "/",
		MaxAge:   int(time.Duration(2160 * time.Hour).Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}

	return cookie
}

func getUserCookie(r *http.Request, jwtSecret string) (subject string, ok bool) {
	cookie, err := r.Cookie(CookieName)
	if err != nil {
		logger.Debug("no cookie found", "err", err)
		return subject, false
	}

	key := []byte(jwtSecret)
	verifier, err := jwt.NewVerifierHS(jwt.HS256, key)
	if err != nil {
		logger.Debug("failed to create jwt verifier", "err", err)
		return subject, false
	}

	cookieVal := []byte(cookie.Value)
	newToken, err := jwt.Parse(cookieVal, verifier)
	if err != nil {
		logger.Debug("failed to parse cookie", "err", err)
		return subject, false
	}

	var claims jwt.RegisteredClaims
	if err = json.Unmarshal(newToken.Claims(), &claims); err != nil {
		logger.Debug("failed to unmarshal jwt claims", "err", err)
		return subject, false
	}

	return claims.Subject, true
}

func getUserData(accessToken AccessTokenBody) (user User, ok bool) {
	req, err := http.NewRequest("GET", "https://oauth.reddit.com/api/v1/me", nil)
	if err != nil {
		logger.Debug("error creating user data request", "err", err)
		return user, false
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", accessToken.AccessToken))

	res, err := client.Do(req)
	if err != nil {
		logger.Debug("error retrieving user data request", "err", err)
		return user, false
	}
	defer res.Body.Close()
	var userResponse UserResponse

	body, err := io.ReadAll(res.Body)
	if err != nil {
		logger.Debug("error reading response body", "err", err)
		return user, false
	}
	err = json.Unmarshal(body, &userResponse)
	if err != nil {
		logger.Debug("failed to unmarshal", "body", string(body), ", err: ", err)
	} else {
		user.IconUrl = strings.Replace(userResponse.Data.IconImg, "&amp;", "&", -1)
	}

	user.Username = userResponse.Data.Username
	user.AccessToken = accessToken.AccessToken
	user.RefreshExpireDtTm = accessToken.GetExpireDtTm()
	user.RefreshToken = accessToken.RefreshToken
	return user, true
}

func (r RealRedditAuthCaller) callRefreshAccessTokenApi(postBody PostBody) (*http.Response, error) {
	data := url.Values{}
	data.Set("grant_type", postBody.GrantType)
	data.Set("refresh_token", postBody.RefreshToken)

	req, err := http.NewRequest("POST", "https://www.reddit.com/api/v1/access_token", strings.NewReader(data.Encode()))

	if err != nil {
		logger.Debug("failed to create post request", "err", err)
		return nil, err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Basic %s", r.envs.basicAuth))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	return client.Do(req)
}

func (r RealRedditAuthCaller) callAccessTokenApi(postBody PostBody) (*http.Response, error) {
	data := url.Values{}
	data.Set("grant_type", postBody.GrantType)
	data.Set("code", postBody.Code)
	data.Set("redirect_uri", postBody.RedirectUri)

	req, err := http.NewRequest("POST", "https://www.reddit.com/api/v1/access_token", strings.NewReader(data.Encode()))

	if err != nil {
		logger.Debug("failed to create post request", "err", err)
		return nil, err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Basic %s", r.envs.basicAuth))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	return client.Do(req)
}

func getAccessToken(postBody PostBody, callApi func(PostBody) (*http.Response, error)) (accessToken *AccessTokenBody, ok bool) {
	res, err := callApi(postBody)
	if err != nil {
		logger.Debug("failed to get access token", "err", err)
		return nil, false
	}

	defer func() {
		if err := res.Body.Close(); err != nil {
			logger.Debug("error closing body", "err", err)
		}
	}()

	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		logger.Debug("failed to read response body", "err", err)
		return nil, false
	}

	err = json.Unmarshal(resBody, &accessToken)
	if err != nil {
		logger.Debug("failed to unmarshall response", "err", err)
		return nil, false
	}
	return accessToken, true

}

func (r RealRedditAuthCaller) getRedditAccessToken(state string, code string) (accessToken *AccessTokenBody, ok bool) {
	if state != r.envs.oauthState {
		logger.Debug("incorrect oauth state", "state", state, "expectedState", r.envs.oauthState)
		return nil, false
	}

	if code == "" {
		logger.Debug("incorrect oauth code", "code", code)
		return nil, false
	}

	body := PostBody{
		GrantType:   "authorization_code",
		Code:        code,
		RedirectUri: r.envs.redirectUri,
	}
	return getAccessToken(body, r.callAccessTokenApi)
}

func refreshAccessToken(user *User, callApi func(PostBody) (*http.Response, error)) (*User, bool) {
	var accessToken *AccessTokenBody
	body := PostBody{
		GrantType:    "refresh_token",
		RefreshToken: user.RefreshToken,
	}

	res, err := callApi(body)
	if err != nil {
		logger.Debug("failed to get access token", "err", err)
		return user, false
	}

	defer func() {
		if err := res.Body.Close(); err != nil {
			logger.Debug("error closing body", "err", err)
		}
	}()

	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		logger.Debug("failed to read response body", "err", err)
		return user, false
	}

	err = json.Unmarshal(resBody, &accessToken)
	if err != nil {
		logger.Debug("error unmarshalling response", "err", err)
		return user, false
	}
	user.AccessToken = accessToken.AccessToken
	user.RefreshExpireDtTm = accessToken.GetExpireDtTm()
	return user, true

}

func (r RealRedditAuthCaller) refreshRedditAccessToken(user *User) (*User, bool) {
	return refreshAccessToken(user, r.callRefreshAccessTokenApi)
}
