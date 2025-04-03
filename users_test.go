package redditgo

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

var jwtSecret string = "secret"

type FakeClock struct{}

func (FakeClock) Now() time.Time {
	dttm, _ := time.Parse("2006-01-02T15:04:05+0000", "2024-10-20T00:00:00+0000")
	return dttm
}

type FakeRedditAuthCaller struct{ envs *ClientEnvs }

func (FakeRedditAuthCaller) callAccessTokenApi(postBody PostBody) (*http.Response, error) {
	tokenBody := AccessTokenBody{AccessToken: "test"}
	tokenBodyBytes, _ := json.Marshal(tokenBody)

	res := http.Response{}
	res.Body = io.NopCloser(bytes.NewReader(tokenBodyBytes))

	return &res, nil
}

func (FakeRedditAuthCaller) callRefreshAccessTokenApi(postBody PostBody) (*http.Response, error) {
	tokenBody := AccessTokenBody{AccessToken: "accesstoken", ExpiresIn: 86400}
	tokenBodyBytes, _ := json.Marshal(tokenBody)

	res := http.Response{}
	res.Body = io.NopCloser(bytes.NewReader(tokenBodyBytes))

	return &res, nil
}

func (f FakeRedditAuthCaller) getRedditAccessToken(state string, code string) (accessToken *AccessTokenBody, ok bool) {
	if state != f.envs.oauthState {
		logger.Debug("incorrect oauth state", "state", state, "expectedState", f.envs.oauthState)
		return nil, false
	}

	if code == "" {
		logger.Debug("incorrect oauth code", "code", code)
		return nil, false
	}

	body := PostBody{
		GrantType:   "authorization_code",
		Code:        code,
		RedirectUri: f.envs.redirectUri,
	}

	return getAccessToken(body, f.callAccessTokenApi)
}

func (f FakeRedditAuthCaller) refreshRedditAccessToken(user *User) (*User, bool) {
	return refreshAccessToken(user, f.callRefreshAccessTokenApi)
}

type ErrorRedditAuthCaller struct{ envs *ClientEnvs }

func (ErrorRedditAuthCaller) callAccessTokenApi(postBody PostBody) (*http.Response, error) {
	return nil, errors.New("test")
}

func (ErrorRedditAuthCaller) callRefreshAccessTokenApi(postBody PostBody) (*http.Response, error) {
	return nil, errors.New("test")
}

func (ErrorRedditAuthCaller) getRedditAccessToken(state string, code string) (accessToken *AccessTokenBody, ok bool) {
	return accessToken, false
}

func (e ErrorRedditAuthCaller) refreshRedditAccessToken(user *User) (*User, bool) {
	body := PostBody{
		GrantType:    "refresh_token",
		RefreshToken: user.RefreshToken,
	}

	_, err := e.callRefreshAccessTokenApi(body)
	if err != nil {
		logger.Debug("failed to get access token", "err", err)
		return user, false
	}
	return nil, true
}

var userTestClientEnvs = ClientEnvs{
	jwtSecret:   "test",
	oauthState:  "state",
	basicAuth:   "basic",
	redirectUri: "123",
}

var fakeAuthCaller = FakeRedditAuthCaller{envs: &userTestClientEnvs}
var errorAuthCaller = ErrorRedditAuthCaller{envs: &userTestClientEnvs}

func setup() {
	// main()
	clock = FakeClock{}
}

func TestMain(m *testing.M) {
	// Setup code here
	setup()

	// Run the tests
	exitCode := m.Run()
	// Teardown code here
	// teardown()
	os.Exit(exitCode)
}

func TestCreateUserJwt(t *testing.T) {
	username := "test"
	want := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0IiwiZXhwIjoxNzI5NDY4ODAwfQ.o6g35x0DLhID8hLzn9DmUQa_2ZQOob2h9-QgG2yaEy8"

	jwt := createUserJwt(username, jwtSecret)

	if !cmp.Equal(jwt, want) {
		t.Fatalf(`CreateUserJwt("%v") = %s, want match for %s`, username, jwt, want)
	}
}

func TestCreateUserCookie(t *testing.T) {
	user := UserCookie{Username: "test"}
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0IiwiZXhwIjoxNzI5NDY4ODAwfQ.o6g35x0DLhID8hLzn9DmUQa_2ZQOob2h9-QgG2yaEy8"

	want := http.Cookie{
		Name:     CookieName,
		Value:    jwt,
		Path:     "/",
		MaxAge:   int(time.Duration(2160 * time.Hour).Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}

	cookie := createUserCookie(user, jwtSecret)

	if !cmp.Equal(cookie, want) {
		t.Fatalf(`CreateUserCookie("%v") = %v, want match for %v`, user, cookie, want)
	}
}

func TestGetUserCookie_CookieMissing(t *testing.T) {
	var want string
	wantOk := false
	req := &http.Request{}

	subject, ok := getUserCookie(req, jwtSecret)

	if !cmp.Equal(subject, want) || !cmp.Equal(ok, wantOk) {
		t.Fatalf(`GetUserCookie("%v") = %v, %t, want match for %v, %t`, req, subject, ok, want, wantOk)
	}
}

func TestGetUserCookie_CookieParseFailure_BadFormat(t *testing.T) {
	var want string
	wantOk := false
	jwt := "badformat"

	wantCookie := http.Cookie{
		Name:     CookieName,
		Value:    jwt,
		Path:     "/",
		MaxAge:   int(time.Duration(2160 * time.Hour).Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}

	req := http.Request{}
	req.Header = make(http.Header)
	req.AddCookie(&wantCookie)

	subject, ok := getUserCookie(&req, jwtSecret)

	if !cmp.Equal(subject, want) || ok != wantOk {
		t.Fatalf(`GetUserCookie("%v") = %v, %t, want match for %v, %t`, req, subject, ok, want, wantOk)
	}
}

func TestGetUserCookie_CookieParseFailure_Badjwt(t *testing.T) {
	var want string
	wantOk := false
	t.Setenv("REDDIT_JWT_SECRET", "secret")
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0IiwiZXhwIjoxNzI5NDY4ODAwfQ.o6g35x0DLhID8hLzn9DmUQa_2ZQOob2h9-QgG2yaEyf"

	wantCookie := http.Cookie{
		Name:     CookieName,
		Value:    jwt,
		Path:     "/",
		MaxAge:   int(time.Duration(2160 * time.Hour).Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}

	req := http.Request{}
	req.Header = make(http.Header)
	req.AddCookie(&wantCookie)

	subject, ok := getUserCookie(&req, jwtSecret)

	if !cmp.Equal(subject, want) || ok != wantOk {
		t.Fatalf(`GetUserCookie("%v") = %v, %t, want match for %v, %t`, req, subject, ok, want, wantOk)
	}
}

func TestGetUserCookie_CookieDataAccess_SubjectReturned(t *testing.T) {
	want, wantOk := "test", true

	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0IiwiZXhwIjoxNzI5NDY4ODAwfQ.o6g35x0DLhID8hLzn9DmUQa_2ZQOob2h9-QgG2yaEy8"

	wantCookie := http.Cookie{
		Name:     CookieName,
		Value:    jwt,
		Path:     "/",
		MaxAge:   int(time.Duration(2160 * time.Hour).Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}

	req := http.Request{}
	req.Header = make(http.Header)
	req.AddCookie(&wantCookie)

	subject, ok := getUserCookie(&req, jwtSecret)

	if !cmp.Equal(subject, want) || ok != wantOk {
		t.Fatalf(`GetUserCookie("%v") = %v, %t, want match for %v, %t`, req, subject, ok, want, wantOk)
	}
}

func TestGetRedditAccessToken_SuccessResponse(t *testing.T) {
	state := "state"
	code := "code"

	want := &AccessTokenBody{AccessToken: "test"}
	wantOk := true

	tokenBody, ok := fakeAuthCaller.getRedditAccessToken(state, code)

	if !cmp.Equal(tokenBody, want) || ok != wantOk {
		t.Fatalf(`GetRedditAccessToken("%s, %s") = %v, %t, want match for %v, %t`, state, code, tokenBody, ok, want, wantOk)
	}
}

func TestGetRedditAccessToken_ErrorResponse(t *testing.T) {
	state := "state"
	code := "code"

	want := &AccessTokenBody{}
	wantOk := false

	tokenBody, ok := errorAuthCaller.getRedditAccessToken(state, code)

	if !cmp.Equal(tokenBody, want) && ok != wantOk {
		t.Fatalf(`GetRedditAccessToken("%s, %s") = %v, %t, want match for %v, %t`, state, code, tokenBody, ok, want, wantOk)
	}
}

func TestRefreshRedditAccessToken_SuccessResponse(t *testing.T) {
	want := &User{UserCookie: UserCookie{Username: "test", AccessToken: "accesstoken", RefreshExpireDtTm: clock.Now().Add(24 * time.Hour)}, RefreshToken: "refresh"}
	wantOk := true

	refreshUser := User{RefreshToken: "refresh", UserCookie: UserCookie{Username: "test"}}

	user, ok := fakeAuthCaller.refreshRedditAccessToken(&refreshUser)

	if !cmp.Equal(user, want) || ok != wantOk {
		t.Fatalf(`GetRedditAccessToken("%v") = %v, %t, want match for %v, %t`, refreshUser, user, ok, want, wantOk)
	}
}

func TestRefreshRedditAccessToken_ErrorResponse(t *testing.T) {
	want := &User{RefreshToken: "refresh"}
	wantOk := false

	refreshUser := User{RefreshToken: "refresh"}

	user, ok := errorAuthCaller.refreshRedditAccessToken(&refreshUser)

	if !cmp.Equal(user, want) || ok != wantOk {
		t.Fatalf(`GetRedditAccessToken("%v") = %v, %t, want match for %v, %t`, refreshUser, user, ok, want, wantOk)
	}
}
