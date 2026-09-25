// Copyright 2026 The pii-scanner Authors
// SPDX-License-Identifier: Apache-2.0

// Package cicomment creates or updates the pii-scanner summary comment on a
// GitHub pull request or GitLab merge request, so CI templates need no
// extra tools (gh, jq) to post it.
//
// The HTTP client, environment and file reader are injected, so the
// GitHub/GitLab conversations can be tested against httptest servers.
package cicomment

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Marker identifies the comment to update.
const Marker = "<!-- pii-scanner-report -->"

// ErrNotInReview is returned when not running for a PR/MR.
var ErrNotInReview = errors.New("not running for a pull/merge request")

// Doer sends HTTP requests (*http.Client satisfies it).
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

// Client posts review comments.
type Client struct {
	HTTP Doer
	// Getenv reads CI variables (os.Getenv in production).
	Getenv func(string) string
	// ReadFile reads the GitHub event payload (os.ReadFile in production).
	ReadFile func(string) ([]byte, error)
}

// Post upserts body (which should contain Marker) on the current PR/MR,
// detected from the CI environment.
func (c Client) Post(body string) (string, error) {
	if !strings.Contains(body, Marker) {
		body = Marker + "\n" + body
	}
	switch {
	case c.Getenv("GITHUB_ACTIONS") == "true":
		return c.postGitHub(body)
	case c.Getenv("GITLAB_CI") == "true":
		return c.postGitLab(body)
	}
	return "", errors.New("unsupported CI: expected GitHub Actions or GitLab CI")
}

func (c Client) do(method, u string, hdr map[string]string, in any, out any) error {
	var r io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, u, r)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s %s: %s: %s", method, u, resp.Status, strings.TrimSpace(string(data)))
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

func (c Client) postGitHub(body string) (string, error) {
	token := c.Getenv("GITHUB_TOKEN")
	repo := c.Getenv("GITHUB_REPOSITORY")
	api := c.Getenv("GITHUB_API_URL")
	if api == "" {
		api = "https://api.github.com"
	}
	if token == "" || repo == "" {
		return "", errors.New("GITHUB_TOKEN and GITHUB_REPOSITORY are required")
	}
	pr := c.prNumber()
	if pr == 0 {
		return "", ErrNotInReview
	}
	hdr := map[string]string{"Authorization": "Bearer " + token, "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
	var comments []struct {
		ID   int64  `json:"id"`
		Body string `json:"body"`
	}
	if err := c.do("GET", fmt.Sprintf("%s/repos/%s/issues/%d/comments?per_page=100", api, repo, pr), hdr, nil, &comments); err != nil {
		return "", err
	}
	for _, cm := range comments {
		if strings.Contains(cm.Body, Marker) {
			err := c.do("PATCH", fmt.Sprintf("%s/repos/%s/issues/comments/%d", api, repo, cm.ID), hdr, map[string]string{"body": body}, nil)
			return "updated", err
		}
	}
	err := c.do("POST", fmt.Sprintf("%s/repos/%s/issues/%d/comments", api, repo, pr), hdr, map[string]string{"body": body}, nil)
	return "created", err
}

func (c Client) prNumber() int {
	path := c.Getenv("GITHUB_EVENT_PATH")
	if path == "" || c.ReadFile == nil {
		return 0
	}
	b, err := c.ReadFile(path)
	if err != nil {
		return 0
	}
	var ev struct {
		PullRequest *struct {
			Number int `json:"number"`
		} `json:"pull_request"`
	}
	if json.Unmarshal(b, &ev) != nil || ev.PullRequest == nil {
		return 0
	}
	return ev.PullRequest.Number
}

func (c Client) postGitLab(body string) (string, error) {
	api := c.Getenv("CI_API_V4_URL")
	project := c.Getenv("CI_PROJECT_ID")
	mr := c.Getenv("CI_MERGE_REQUEST_IID")
	if mr == "" {
		return "", ErrNotInReview
	}
	token := c.Getenv("PII_SCANNER_GITLAB_TOKEN")
	if token == "" {
		return "", errors.New("set PII_SCANNER_GITLAB_TOKEN (a project access token with api scope) to post merge request notes")
	}
	hdr := map[string]string{"PRIVATE-TOKEN": token}
	base := fmt.Sprintf("%s/projects/%s/merge_requests/%s/notes", api, url.PathEscape(project), mr)
	var notes []struct {
		ID   int64  `json:"id"`
		Body string `json:"body"`
	}
	if err := c.do("GET", base+"?per_page=100&sort=desc", hdr, nil, &notes); err != nil {
		return "", err
	}
	for _, n := range notes {
		if strings.Contains(n.Body, Marker) {
			err := c.do("PUT", fmt.Sprintf("%s/%d", base, n.ID), hdr, map[string]string{"body": body}, nil)
			return "updated", err
		}
	}
	err := c.do("POST", base, hdr, map[string]string{"body": body}, nil)
	return "created", err
}
