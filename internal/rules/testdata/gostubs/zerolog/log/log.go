// Package log is an offline stand-in for github.com/rs/zerolog/log.
package log

import "github.com/rs/zerolog"

var Logger zerolog.Logger

func Info() *zerolog.Event                   { return Logger.Info() }
func Printf(format string, v ...interface{}) {}
