// Package log is an offline stand-in for github.com/go-kit/log.
package log

import "io"

type Logger interface {
	Log(keyvals ...interface{}) error
}

type logger struct{}

func (logger) Log(keyvals ...interface{}) error { return nil }

func NewLogfmtLogger(w io.Writer) Logger                 { return logger{} }
func With(l Logger, keyvals ...interface{}) Logger       { return l }
func WithPrefix(l Logger, keyvals ...interface{}) Logger { return l }
