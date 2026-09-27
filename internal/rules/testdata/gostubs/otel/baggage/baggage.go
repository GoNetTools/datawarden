// Package baggage is a stub of go.opentelemetry.io/otel/baggage for the rule examples.
package baggage

import "context"

type Member struct{ key, value string }
type Baggage struct{ members []Member }

func NewMember(key, value string) (Member, error)                       { return Member{key, value}, nil }
func New(members ...Member) (Baggage, error)                            { return Baggage{members}, nil }
func ContextWithBaggage(ctx context.Context, b Baggage) context.Context { return ctx }
