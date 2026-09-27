// Package ddtrace is a stub of gopkg.in/DataDog/dd-trace-go.v1/ddtrace for the rule examples.
package ddtrace

type Span interface {
	SetTag(key string, value interface{})
	Finish()
}
