// Package attribute is a stub of go.opentelemetry.io/otel/attribute for the rule examples.
package attribute

type KeyValue struct {
	Key   string
	Value string
}

func String(k, v string) KeyValue  { return KeyValue{Key: k, Value: v} }
func Int(k string, v int) KeyValue { return KeyValue{Key: k} }
