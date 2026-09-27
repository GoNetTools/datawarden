// Package libhoney is a stub of github.com/honeycombio/libhoney-go for the rule examples.
package libhoney

type Event struct{}

func NewEvent() *Event                                { return &Event{} }
func (e *Event) AddField(key string, val interface{}) {}
func (e *Event) Add(data interface{}) error           { return nil }
func (e *Event) Send() error                          { return nil }
