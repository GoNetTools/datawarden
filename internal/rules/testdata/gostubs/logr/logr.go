// Package logr is an offline stand-in for github.com/go-logr/logr.
package logr

type Logger struct{}

func Discard() Logger                                           { return Logger{} }
func (l Logger) Info(msg string, kv ...interface{})             {}
func (l Logger) Error(err error, msg string, kv ...interface{}) {}
func (l Logger) WithValues(kv ...interface{}) Logger            { return l }
func (l Logger) WithName(name string) Logger                    { return l }
func (l Logger) V(level int) Logger                             { return l }
