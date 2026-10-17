// Package glog is an offline stand-in for github.com/golang/glog.
package glog

func Info(args ...interface{})                    {}
func Infof(format string, args ...interface{})    {}
func Warningf(format string, args ...interface{}) {}
func Errorf(format string, args ...interface{})   {}
