// Package log is a stub of go.opentelemetry.io/otel/log for the rule examples.
package log

import "context"

type Value struct{ s string }
type KeyValue struct {
	Key   string
	Value Value
}

func StringValue(v string) Value  { return Value{v} }
func String(k, v string) KeyValue { return KeyValue{k, Value{v}} }

type Record struct{ body Value }

func (r *Record) SetBody(v Value)                 { r.body = v }
func (r *Record) AddAttributes(attrs ...KeyValue) {}

type Logger interface {
	Emit(ctx context.Context, r Record)
}
