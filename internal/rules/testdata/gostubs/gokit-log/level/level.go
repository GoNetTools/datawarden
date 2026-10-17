// Package level is an offline stand-in for github.com/go-kit/log/level.
package level

import "github.com/go-kit/log"

func Info(l log.Logger) log.Logger  { return l }
func Error(l log.Logger) log.Logger { return l }
