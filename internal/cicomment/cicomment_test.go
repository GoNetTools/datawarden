// Copyright 2026 The piiflow Authors
// SPDX-License-Identifier: Apache-2.0

package cicomment

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

type fakeForge struct {
	mu       sync.Mutex
	existing string // body of an existing comment, "" for none
	calls    []string
	lastBody string
}

func (f *fakeForge) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.calls = append(f.calls, r.Method+" "+r.URL.EscapedPath())
		if r.Method != "GET" {
			var in struct{ Body string }
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &in)
			f.lastBody = in.Body
			w.WriteHeader(201)
			_, _ = w.Write([]byte("{}"))
			return
		}
		if f.existing == "" {
			_, _ = w.Write([]byte("[]"))
			return
		}
		_ = json.NewEncoder(w).Encode([]map[string]any{{"id": 7, "body": "other"}, {"id": 42, "body": f.existing}})
	})
}

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestGitHubCreatesThenUpdates(t *testing.T) {
	forge := &fakeForge{}
	srv := httptest.NewServer(forge.handler(t))
	defer srv.Close()
	c := Client{
		HTTP: srv.Client(),
		Getenv: env(map[string]string{"GITHUB_ACTIONS": "true", "GITHUB_TOKEN": "t", "GITHUB_REPOSITORY": "acme/app",
			"GITHUB_API_URL": srv.URL, "GITHUB_EVENT_PATH": "/event.json"}),
		ReadFile: func(string) ([]byte, error) { return []byte(`{"pull_request":{"number":12}}`), nil },
	}
	what, err := c.Post("### piiflow")
	if err != nil || what != "created" || forge.calls[1] != "POST /repos/acme/app/issues/12/comments" {
		t.Fatalf("create: %v %s %v", err, what, forge.calls)
	}
	if !strings.HasPrefix(forge.lastBody, Marker) {
		t.Error("marker not added")
	}
	forge.existing, forge.calls = Marker+"\nold", nil
	what, err = c.Post(Marker + "\nnew")
	if err != nil || what != "updated" || forge.calls[1] != "PATCH /repos/acme/app/issues/comments/42" {
		t.Fatalf("update: %v %s %v", err, what, forge.calls)
	}
}

func TestGitLabNeedsTokenAndMR(t *testing.T) {
	forge := &fakeForge{existing: Marker}
	srv := httptest.NewServer(forge.handler(t))
	defer srv.Close()
	vars := map[string]string{"GITLAB_CI": "true", "CI_API_V4_URL": srv.URL, "CI_PROJECT_ID": "group/app"}
	c := Client{HTTP: srv.Client(), Getenv: env(vars)}
	if _, err := c.Post("x"); !errors.Is(err, ErrNotInReview) {
		t.Errorf("no MR: %v", err)
	}
	vars["CI_MERGE_REQUEST_IID"] = "5"
	if _, err := c.Post("x"); err == nil || !strings.Contains(err.Error(), "PIIFLOW_GITLAB_TOKEN") {
		t.Errorf("missing token: %v", err)
	}
	vars["PIIFLOW_GITLAB_TOKEN"] = "glpat"
	what, err := c.Post("x")
	if err != nil || what != "updated" || !strings.HasPrefix(forge.calls[len(forge.calls)-1], "PUT /projects/group%2Fapp/merge_requests/5/notes/42") {
		t.Errorf("gitlab update: %v %s %v", err, what, forge.calls)
	}
}
