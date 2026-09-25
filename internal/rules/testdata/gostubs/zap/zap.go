// Package zap is an offline stand-in for go.uber.org/zap.
package zap

type Field struct {
	Key    string
	String string
}

func String(key, val string) Field { return Field{Key: key, String: val} }

type Logger struct{}

func NewNop() *Logger                          { return &Logger{} }
func (l *Logger) Info(msg string, f ...Field)  {}
func (l *Logger) Error(msg string, f ...Field) {}
func (l *Logger) Sugar() *SugaredLogger        { return &SugaredLogger{} }

type SugaredLogger struct{}

func (s *SugaredLogger) Infow(msg string, kv ...interface{}) {}
