// Package tracer is a stub of gopkg.in/DataDog/dd-trace-go.v1/ddtrace/tracer for the rule examples.
package tracer

import (
	"context"

	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace"
)

type StartSpanOption func()
type UserMonitoringOption func()

func Tag(k string, v interface{}) StartSpanOption                          { return nil }
func StartSpan(operationName string, opts ...StartSpanOption) ddtrace.Span { return nil }
func SpanFromContext(ctx context.Context) (ddtrace.Span, bool)             { return nil, false }
func SetUser(s ddtrace.Span, id string, opts ...UserMonitoringOption)      {}
func WithUserEmail(email string) UserMonitoringOption                      { return nil }
