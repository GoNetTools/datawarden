// Package zap is an offline stand-in for go.uber.org/zap.
package zap

type Field struct {
	Key    string
	String string
}

func String(key, val string) Field  { return Field{Key: key, String: val} }
func Any(key string, val any) Field { return Field{Key: key} }

type Logger struct{}

func NewNop() *Logger                          { return &Logger{} }
func L() *Logger                               { return &Logger{} }
func S() *SugaredLogger                        { return &SugaredLogger{} }
func (l *Logger) With(f ...Field) *Logger      { return l }
func (l *Logger) Debug(msg string, f ...Field) {}
func (l *Logger) Info(msg string, f ...Field)  {}
func (l *Logger) Warn(msg string, f ...Field)  {}
func (l *Logger) Error(msg string, f ...Field) {}
func (l *Logger) Sugar() *SugaredLogger        { return &SugaredLogger{} }

type SugaredLogger struct{}

func (s *SugaredLogger) Infow(msg string, kv ...interface{})       {}
func (s *SugaredLogger) Errorw(msg string, kv ...interface{})      {}
func (s *SugaredLogger) Infof(format string, args ...interface{})  {}
func (s *SugaredLogger) Errorf(format string, args ...interface{}) {}
func (s *SugaredLogger) With(kv ...interface{}) *SugaredLogger     { return s }
