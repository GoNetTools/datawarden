// Package log is an offline stand-in for github.com/rs/zerolog/log.
package log

import "github.com/rs/zerolog"

var Logger zerolog.Logger

func Info() *zerolog.Event                   { return Logger.Info() }
func Error() *zerolog.Event                  { return Logger.Error() }
func Debug() *zerolog.Event                  { return Logger.Debug() }
func Printf(format string, v ...interface{}) {}
