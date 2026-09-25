// Package logrus is an offline stand-in for github.com/sirupsen/logrus.
package logrus

type Entry struct{}

func (e *Entry) Info(args ...interface{}) {}

func Info(args ...interface{})                       {}
func Infof(format string, args ...interface{})       {}
func WithField(key string, value interface{}) *Entry { return &Entry{} }
