package redditgo

import (
	"log/slog"
	"net/http"
	"os"
)

const USER_AGENT string = "RddtufRuntime:reddituf:1.0.0 by /u/cat_tastrophe"

type ClientEnvs struct {
	JwtSecret   string
	OauthState  string
	BasicAuth   string
	RedirectUri string
}

type Client interface {
	GetRedditDetails(RedditRequest, User) (Post, error)
	GetUserCookie(*http.Request) (string, bool)
	CreateUserCookie(UserCookie) http.Cookie
	GetUserData(AccessTokenBody) (User, bool)
	GetRedditAccessToken(string, string) (*AccessTokenBody, bool)
	RefreshRedditAccessToken(*User) (*User, bool)
}

type RedditClient struct {
	authCaller RedditAuthCaller
	apiCaller  RedditCaller
	clientEnvs ClientEnvs
}

// Creates a new RedditClient to call into the reddit api
func (c *RedditClient) New(clientEnvs ClientEnvs) *RedditClient {
	c.authCaller = RealRedditAuthCaller{envs: &clientEnvs}
	c.apiCaller = RealRedditCaller{}
	c.clientEnvs = clientEnvs
	return c
}

// Retrieve a reddit post details including: image url, comment, author, etc.
// The request contains a specific subreddit, post, and comment, as well as a user for their access token
func (c RedditClient) GetRedditDetails(req RedditRequest, user User) (Post, error) {
	return c.apiCaller.getRedditDetails(req, user)
}

// Parse the reddit go cookie for the users jwt claim subject, returns true if successful, false otherwise
func (c RedditClient) GetUserCookie(req *http.Request) (string, bool) {
	return getUserCookie(req, c.clientEnvs.JwtSecret)
}

// Creates an http cookie for a specific user
func (c RedditClient) CreateUserCookie(userCookie UserCookie) http.Cookie {
	return createUserCookie(userCookie, c.clientEnvs.JwtSecret)
}

// Retreives data for a user including their username and icon img url
func (c RedditClient) GetUserData(accessToken AccessTokenBody) (User, bool) {
	return getUserData(accessToken)
}

// Retrieve the reddit access token for a specific oauth2 application
func (c RedditClient) GetRedditAccessToken(state string, code string) (*AccessTokenBody, bool) {
	return c.authCaller.getRedditAccessToken(state, code)
}

// Refresh the reddit access token for a user assuming it is a permanent token
func (c RedditClient) RefreshRedditAccessToken(user *User) (*User, bool) {
	return c.authCaller.refreshRedditAccessToken(user)
}

var logger *slog.Logger

func init() {
	logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
}
