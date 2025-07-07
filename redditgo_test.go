package redditgo

import (
	"net/http"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

type ClientRedditCaller struct{}

var clientRedditCaller RedditCaller = &ClientRedditCaller{}

func (ClientRedditCaller) callRedditApi(req RedditRequest, user User) (post Post, err error) {
	return post, nil
}

func (ClientRedditCaller) getRedditDetails(req RedditRequest, user User) (post Post, err error) {
	return post, nil
}

func (ClientRedditCaller) unfurlRedditLink(subreddit string, shortLink string, user User) (string, error) {
	return "testing", nil
}

type ClientAuthCaller struct{}

var clientAuthCaller RedditAuthCaller = &ClientAuthCaller{}

func (ClientAuthCaller) getUserCookie(req *http.Request, s string) (string, bool) {
	return "test", true
}

func (ClientAuthCaller) getUserData(accessToken AccessTokenBody) (User, bool) {
	return User{}, true
}

func (ClientAuthCaller) getRedditAccessToken(state string, code string) (*AccessTokenBody, bool) {
	return &AccessTokenBody{}, true
}

func (ClientAuthCaller) refreshRedditAccessToken(user *User) (*User, bool) {
	return user, true
}

func (ClientAuthCaller) callRefreshAccessTokenApi(postBody PostBody) (*http.Response, error) {
	return &http.Response{}, nil
}

func (ClientAuthCaller) callAccessTokenApi(postBody PostBody) (*http.Response, error) {
	return &http.Response{}, nil
}

var testClient Client = &RedditClient{authCaller: clientAuthCaller, apiCaller: clientRedditCaller, clientEnvs: userTestClientEnvs}

func TestClient_GetRedditDetails(t *testing.T) {
	redditReq := RedditRequest{}
	user := User{}
	want := Post{}

	post, err := testClient.GetRedditDetails(redditReq, user)

	if !cmp.Equal(post, want) || err != nil {
		t.Fatalf(`GetRedditDetails("%s, %v") = %s, %v, want match for %s, nil`, redditReq.AsString(), user, post.QueryId, err, want.QueryId)
	}
}

func TestClient_GetUserCookie(t *testing.T) {
	req := &http.Request{}

	want := ""

	subject, ok := testClient.GetUserCookie(req)

	if !cmp.Equal(subject, want) || ok != false {
		t.Fatalf(`GetUserCookie("%v") = %s, %v, want match for %s, false`, req, subject, ok, want)
	}
}

func TestClient_CreateUserCookie(t *testing.T) {
	user := UserCookie{Username: "test"}

	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0IiwiZXhwIjoxNzI5NDY4ODAwfQ.4UiZEnsdX8u2RWhvupO272XCmye8mVIysdBAGFaeMpU"

	want := http.Cookie{
		Name:     CookieName,
		Value:    jwt,
		Path:     "/",
		MaxAge:   int(time.Duration(2160 * time.Hour).Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}

	cookie := testClient.CreateUserCookie(user)

	if !cmp.Equal(cookie, want) {
		t.Fatalf(`GetUserCreateCookie("%v") = %v, want match for %v, false`, user, cookie, want)
	}
}

func TestClient_GetRedditAccessToken(t *testing.T) {
	state := "state"
	code := "code"

	want := &AccessTokenBody{}

	accessToken, ok := testClient.GetRedditAccessToken(state, code)

	if !cmp.Equal(accessToken, want) || ok != true {
		t.Fatalf(`GetRedditAccessToken("%s, %s") = %v, %v, want match for %v, true`, state, code, accessToken, ok, want)
	}
}

func TestClient_RefreshRedditAccessToken(t *testing.T) {
	user := &User{}

	want := user

	finalUser, ok := testClient.RefreshRedditAccessToken(user)

	if !cmp.Equal(finalUser, want) || ok != true {
		t.Fatalf(`RefreshRedditAccessToken("%v") = %v, %v, want match for %v, true`, user, finalUser, ok, want)
	}
}
