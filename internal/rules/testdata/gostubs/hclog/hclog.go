// Package hclog is an offline stand-in for github.com/hashicorp/go-hclog.
package hclog

type Logger interface {
	Trace(msg string, args ...interface{})
	Debug(msg string, args ...interface{})
	Info(msg string, args ...interface{})
	Warn(msg string, args ...interface{})
	Error(msg string, args ...interface{})
	With(args ...interface{}) Logger
	Named(name string) Logger
}

type logger struct{}

func (logger) Trace(msg string, args ...interface{}) {}
func (logger) Debug(msg string, args ...interface{}) {}
func (logger) Info(msg string, args ...interface{})  {}
func (logger) Warn(msg string, args ...interface{})  {}
func (logger) Error(msg string, args ...interface{}) {}
func (l logger) With(args ...interface{}) Logger     { return l }
func (l logger) Named(name string) Logger            { return l }

func Default() Logger { return logger{} }
