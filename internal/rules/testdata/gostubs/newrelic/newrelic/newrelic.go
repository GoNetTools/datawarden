// Package newrelic is a stub of github.com/newrelic/go-agent/v3/newrelic for the rule examples.
package newrelic

import "context"

type Transaction struct{}

func (t *Transaction) AddAttribute(key string, value interface{}) {}
func (t *Transaction) SetUserID(id string)                        {}

type Application struct{}

func (a *Application) RecordCustomEvent(eventType string, params map[string]interface{}) {}

func FromContext(ctx context.Context) *Transaction { return &Transaction{} }
