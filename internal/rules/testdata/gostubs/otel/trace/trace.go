// Package trace is a stub of go.opentelemetry.io/otel/trace for the rule examples.
package trace

import (
	"context"

	"go.opentelemetry.io/otel/attribute"
)

type EventOption interface{ event() }

type eventOption struct{ attrs []attribute.KeyValue }

func (eventOption) event() {}

func WithAttributes(attributes ...attribute.KeyValue) EventOption {
	return eventOption{attrs: attributes}
}

type Span interface {
	SetAttributes(kv ...attribute.KeyValue)
	AddEvent(name string, options ...EventOption)
	RecordError(err error, options ...EventOption)
	SetStatus(code int, description string)
	End()
}

func SpanFromContext(ctx context.Context) Span { return nil }
