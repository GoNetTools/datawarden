// Package zerolog is an offline stand-in for github.com/rs/zerolog.
package zerolog

import "io"

type Event struct{}

func (e *Event) Str(key, val string) *Event                 { return e }
func (e *Event) Interface(key string, v interface{}) *Event { return e }
func (e *Event) Any(key string, v interface{}) *Event       { return e }
func (e *Event) Fields(f interface{}) *Event                { return e }
func (e *Event) Err(err error) *Event                       { return e }
func (e *Event) Msg(msg string)                             {}
func (e *Event) Msgf(format string, v ...interface{})       {}
func (e *Event) Send()                                      {}

type Logger struct{}

func New(w io.Writer) Logger                            { return Logger{} }
func (l Logger) Info() *Event                           { return &Event{} }
func (l Logger) Error() *Event                          { return &Event{} }
func (l Logger) Debug() *Event                          { return &Event{} }
func (l Logger) Printf(format string, v ...interface{}) {}
func (l Logger) Println(v ...interface{})               {}
