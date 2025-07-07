package redditgo

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type RedditRequest struct {
	Subreddit string
	Article   string
	Comment   string
}

func (req RedditRequest) AsString() string {
	return fmt.Sprintf("%s-%s-%s", req.Subreddit, req.Article, req.Comment)
}

type Base string

const (
	Image    Base = "Image"
	External Base = "External"
	Self     Base = "Self"
)

type Post struct {
	ImageUrl  string    `json:"imageUrl"`
	Comments  []Comment `json:"comments,omitempty"`
	PostType  Base      `json:"linkType"`
	QueryId   string    `json:"queryId"`
	Author    string    `json:"author"`
	Title     string    `json:"title"`
	Subreddit string    `json:"subreddit"`
}

type Comment struct {
	Comment string
	Author  string
}

type UserCookie struct {
	Username          string    `json:"username"`
	RefreshExpireDtTm time.Time `json:"refreshExpireDtTm"`
	AccessToken       string    `json:"accessToken,omitempty"`
	IconUrl           string    `json:"iconUrl,omitempty"`
}

type User struct {
	UserCookie
	Subscribed        bool      `json:"subscribed"`
	SubscriptionDtTm  string    `json:"subscriptionDtTm"`
	RefreshToken      string    `json:"refreshToken,omitempty"`
	UserId            int       `json:"userId"`
	RemainingUploads  int       `json:"remainingUploads"`
	UploadRefreshDtTm time.Time `json:"uploadRefreshDtTm"`
}

const (
	jpg  string = "jpg"
	jpeg string = "jpeg"
	png  string = "png"
	webp string = "webp"
)

type JsonData []map[string]interface{}

// var linkCache map[RedditRequest]Post

// var redditAccessToken string
// var CdnBaseUrl string

// var redditCaller RedditCaller

type RedditCaller interface {
	callRedditApi(req RedditRequest, user User) (post Post, err error)
	getRedditDetails(req RedditRequest, user User) (Post, error)
	unfurlRedditLink(subreddit string, shortLink string, user User) (string, error)
}

type RealRedditCaller struct{}

// Parses the json response for the specific comments, recursively calls this until the desired commentId is found
func parseCommentData(data map[string]interface{}, comments []Comment, commentId string, depth int) []Comment {
	logger.Debug("Entering ParseCommentData", "depth", depth)
	comment := Comment{Comment: data["body"].(string), Author: data["author"].(string)}
	updatedComments := append(comments, comment)
	if data["id"].(string) == commentId {
		return updatedComments
	}
	replyComment := data["replies"].(map[string]interface{})["data"].(map[string]interface{})["children"].([]interface{})[0].(map[string]interface{})["data"].(map[string]interface{})
	if replyComment["body"] == nil || replyComment["body"].(string) == "[deleted]" {
		return updatedComments
	}
	logger.Debug("Leaving ParseCommentData", "depth", depth)
	return parseCommentData(replyComment, updatedComments, commentId, depth+1)
}

// Parses the json response for the meta information about the post
func parsePostData(data map[string]interface{}) Post {
	postData := data["data"].(map[string]interface{})["children"].([]interface{})[0].(map[string]interface{})["data"].(map[string]interface{})

	var post Post
	var postType Base
	if postData["is_reddit_media_domain"].(bool) {
		postType = Image
		post.ImageUrl = postData["url_overridden_by_dest"].(string)
	} else {
		if postData["is_self"].(bool) {
			postType = Self
			post.ImageUrl = "self.jpg"
		} else {
			postType = External
			imageUrlParts := strings.Split(postData["url_overridden_by_dest"].(string), ".")
			ext := imageUrlParts[len(imageUrlParts)-1]
			if ext != jpeg && ext != jpg && ext != png {
				post.ImageUrl = postData["thumbnail"].(string)
			} else {
				post.ImageUrl = postData["url_overridden_by_dest"].(string)
			}
		}
	}
	post.Author = postData["author"].(string)
	post.Title = postData["title"].(string)
	post.PostType = postType
	post.Subreddit = strings.ToLower(postData["subreddit_name_prefixed"].(string))

	return post
}

func parseJsonData(data []map[string]interface{}, redditRequest RedditRequest) Post {
	logger.Debug("Entering ParseJsonData")

	postNode := data[0]
	post := parsePostData(postNode)

	commentNode := data[1]
	firstComment := commentNode["data"].(map[string]interface{})["children"].([]interface{})[0].(map[string]interface{})["data"].(map[string]interface{})

	comments := make([]Comment, 0, 5)
	comments = parseCommentData(firstComment, comments, redditRequest.Comment, 0)
	post.Comments = comments
	post.QueryId = redditRequest.AsString()
	logger.Debug("Leaving ParseJsonData")

	return post
}

func parseApiResponse(res *http.Response, req RedditRequest) (post Post, err error) {
	logger.Debug("Entering ParseApiResponse", "status code", res.StatusCode)
	if res.StatusCode == http.StatusOK {
		body, err := io.ReadAll(res.Body)
		if err != nil {
			logger.Debug("error reading response", "err", err)
			return post, err
		}

		jsonData := make(JsonData, 2)
		for i := range jsonData {
			jsonData[i] = make(map[string]interface{})
		}

		err = json.Unmarshal(body, &jsonData)
		if err != nil {
			logger.Debug("error unmarshalling", "err", err)
			return post, err
		}
		post = parseJsonData(jsonData, req)
		logger.Debug("Leaving ParseApiResponse")
		return post, nil
	}
	logger.Debug("Leaving ParseApiResponse")
	return post, nil
}

// Sets up https call to reddit oauth endpoint
func (r RealRedditCaller) callRedditApi(req RedditRequest, user User) (post Post, err error) {
	logger.Debug("Request: ", "req", req)

	base := "https://oauth.reddit.com"
	subreddit := fmt.Sprintf("r/%s", req.Subreddit)
	article := fmt.Sprintf("comments/%s.json", req.Article)
	comment := fmt.Sprintf("?comment=%s", req.Comment)
	context := fmt.Sprintf("&context=%s", "3")
	limit := fmt.Sprintf("&limit=%s", "5")
	showmedia := fmt.Sprintf("&showmedia=%s", "true")

	requestUrl, err := url.JoinPath(base, subreddit, article)
	if err != nil {
		logger.Debug("Error calling reddit api", "err", err)
	}

	requestUrl = fmt.Sprintf("%s%s%s%s%s", requestUrl, comment, context, limit, showmedia)

	logger.Debug("Making request", "url", requestUrl)

	dataRequest, err := http.NewRequest("GET", requestUrl, nil)
	dataRequest.Header.Add("Authorization", fmt.Sprintf("Bearer %s", user.AccessToken))
	dataRequest.Header.Add("User-Agent", USER_AGENT)

	res, err := client.Do(dataRequest)

	if err != nil {
		logger.Debug("Error calling the reddit api", "res", res)
	}
	defer res.Body.Close()

	switch res.StatusCode {
	case 401:
		return post, errors.New("not authorized")
	case 429:
		return post, errors.New("too many requests")
	}

	return parseApiResponse(res, req)
}

func (r RealRedditCaller) getRedditDetails(req RedditRequest, user User) (Post, error) {
	logger.Debug("Entering getRedditDetails")
	res, err := r.callRedditApi(req, user)
	if err != nil {
		logger.Debug("error calling reddit api: ", "err", err)
		return res, err
	}
	logger.Debug("Leaving getRedditDetails")
	return res, nil
}

func (r RealRedditCaller) unfurlRedditLink(subreddit string, shortLink string, user User) (link string, err error) {
	base := "https://oauth.reddit.com"
	requestUrl, err := url.JoinPath(base, fmt.Sprintf("r/%s/s/%s", subreddit, shortLink))
	if err != nil {
		logger.Debug("Error calling reddit api", "err", err)
	}

	logger.Debug("Making request", "url", requestUrl)

	dataRequest, err := http.NewRequest("GET", requestUrl, nil)
	dataRequest.Header.Add("Authorization", fmt.Sprintf("Bearer %s", user.AccessToken))
	dataRequest.Header.Add("User-Agent", USER_AGENT)

	res, err := client.Do(dataRequest)

	if err != nil {
		if err == http.ErrUseLastResponse {
			logger.Debug("Redirect was prevented")
		} else {
			logger.Debug("Error calling the reddit api", "res", res)
		}
	}
	defer res.Body.Close()

	switch res.StatusCode {
	case 401:
		return link, errors.New("not authorized")
	case 429:
		return link, errors.New("too many requests")
	}

	return res.Header.Get("Location"), nil
}
