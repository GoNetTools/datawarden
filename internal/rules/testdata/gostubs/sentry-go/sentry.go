// Package sentry is an offline stand-in for github.com/getsentry/sentry-go.
package sentry

type User struct {
	ID    string
	Email string
}

type Scope struct{}

func (s *Scope) SetUser(u User)                     {}
func (s *Scope) SetExtra(key string, v interface{}) {}
func (s *Scope) SetTag(key, value string)           {}
func ConfigureScope(f func(*Scope))                 { f(&Scope{}) }
func CaptureMessage(msg string) *string             { return nil }
