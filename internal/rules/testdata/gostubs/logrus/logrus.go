// Package logrus is an offline stand-in for github.com/sirupsen/logrus.
package logrus

type Fields map[string]interface{}

type Entry struct{}

func (e *Entry) Info(args ...interface{})  {}
func (e *Entry) Error(args ...interface{}) {}
func (e *Entry) Warn(args ...interface{})  {}

type Logger struct{}

func (l *Logger) Info(args ...interface{})                  {}
func (l *Logger) Errorf(format string, args ...interface{}) {}
func (l *Logger) WithFields(f Fields) *Entry                { return &Entry{} }

func StandardLogger() *Logger                        { return &Logger{} }
func Info(args ...interface{})                       {}
func Infof(format string, args ...interface{})       {}
func Errorf(format string, args ...interface{})      {}
func Fatalf(format string, args ...interface{})      {}
func Trace(args ...interface{})                      {}
func WithField(key string, value interface{}) *Entry { return &Entry{} }
func WithFields(f Fields) *Entry                     { return &Entry{} }
func WithError(err error) *Entry                     { return &Entry{} }
