// Package klog is an offline stand-in for k8s.io/klog/v2.
package klog

type Verbose bool

func V(level int) Verbose                                  { return true }
func (v Verbose) Info(args ...interface{})                 {}
func (v Verbose) Infof(format string, args ...interface{}) {}
func (v Verbose) InfoS(msg string, kv ...interface{})      {}
func Info(args ...interface{})                             {}
func Infof(format string, args ...interface{})             {}
func InfoS(msg string, kv ...interface{})                  {}
func Warningf(format string, args ...interface{})          {}
func Errorf(format string, args ...interface{})            {}
func ErrorS(err error, msg string, kv ...interface{})      {}
func Fatalf(format string, args ...interface{})            {}
