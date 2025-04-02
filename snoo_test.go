package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
)

type FakeRedditCaller struct{}

var testRedditCaller RedditCaller = &FakeRedditCaller{}

func (f FakeRedditCaller) callRedditApi(req RedditRequest, user User) (post Post, err error) {
	body, err := os.ReadFile("./test/test.json")
	if err != nil {
		fmt.Println(err)
	}

	jsonData := make(JsonData, 2)
	for i := range jsonData {
		jsonData[i] = make(map[string]interface{})
	}

	err = json.Unmarshal(body, &jsonData)
	if err != nil {
		log.Printf("error unmarshalling: %s\n", err)
	}
	post = parseJsonData(jsonData, req)
	return post, nil
}

func (f FakeRedditCaller) getRedditDetails(req RedditRequest, user User) (Post, error) {
	res, err := f.callRedditApi(req, user)
	if err != nil {
		logger.Debug("error calling reddit api: ", "err", err)
		return res, err
	}
	return res, nil
}

type ErrorRedditCaller struct{}

var errorRedditCaller RedditCaller = &ErrorRedditAuthCaller{}

func (e ErrorRedditAuthCaller) callRedditApi(req RedditRequest, user User) (post Post, err error) {
	return post, errors.New("error")
}

func (e ErrorRedditAuthCaller) getRedditDetails(req RedditRequest, user User) (Post, error) {
	res, err := e.callRedditApi(req, user)
	if err != nil {
		logger.Debug("error calling reddit api: ", "err", err)
		return res, err
	}
	return res, nil
}

func TestNewPost_Returned(t *testing.T) {
	redditReq := RedditRequest{Subreddit: "pics", Article: "1fe0l1d", Comment: "lmlaavt"}
	userId := 1
	user := User{UserId: userId}
	cmt1 := Comment{Comment: "Just here to watch people who voted for the host of “Celebrity Apprentice” (who had never held elected office before running for President) say that nobody should care what a celebrity says.", Author: "MyDesign630"}
	cmt2 := Comment{Comment: "Go read the replies to FuckJerry’s Instagram announcing Swift is voting for Harris. Every reply is “people who care about who celebs vote for are losers”", Author: "Chessh2036"}
	cmt3 := Comment{Comment: "Weird for a group that seems to care a lot about what Kevin Sorbo and Kid Rock thinks, even though I never hear about them anymore otherwise.", Author: "mtaw"}
	cmts := []Comment{cmt1, cmt2, cmt3}
	want := Post{Comments: cmts,
		ImageUrl: "https://i.redd.it/h2y07ob2m3od1.png",
		PostType: Image,
		QueryId:  redditReq.AsString(),
		Author:   "Xtianus21",
		Title:    "Taylor Swift with a Cat Named Benjamin Button"}

	post, err := testRedditCaller.getRedditDetails(redditReq, user)

	if !cmp.Equal(post, want) || err != nil {
		t.Fatalf(`callRedditApi("%s, %v") = %s, %v, want match for %s, nil`, redditReq.AsString(), user, post.QueryId, err, want.QueryId)
	}
}

func TestNewPost_Error(t *testing.T) {
	redditReq := RedditRequest{Subreddit: "pics", Article: "1fe0l1d", Comment: "lmlaavt"}
	userId := 1
	user := User{UserId: userId}

	want := Post{}
	wantErr := errors.New("error")

	post, err := errorRedditCaller.getRedditDetails(redditReq, user)

	if !cmp.Equal(post, want) || !cmp.Equal(err.Error(), wantErr.Error()) {
		t.Fatalf(`callRedditApi("%s, %v") = %s, %v, want match for %s, nil`, redditReq.AsString(), user, post.QueryId, err, want.QueryId)
	}
}
