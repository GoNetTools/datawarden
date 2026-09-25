// Package zerolog is an offline stand-in for github.com/rs/zerolog.
package zerolog

type Event struct{}

func (e *Event) Str(key, val string) *Event { return e }
func (e *Event) Msg(msg string)             {}

type Logger struct{}

func (l Logger) Info() *Event { return &Event{} }
