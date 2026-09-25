// Package analytics is an offline stand-in for github.com/segmentio/analytics-go/v3.
package analytics

type Message interface{}

type Properties map[string]interface{}

func NewProperties() Properties { return Properties{} }

func (p Properties) Set(name string, value interface{}) Properties { p[name] = value; return p }

type Track struct {
	UserId     string
	Event      string
	Properties Properties
}

type Client interface {
	Enqueue(Message) error
	Close() error
}

type client struct{}

func (client) Enqueue(Message) error { return nil }
func (client) Close() error          { return nil }

func New(writeKey string) Client { return client{} }
