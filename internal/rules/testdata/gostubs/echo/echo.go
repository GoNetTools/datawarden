// Package echo is a stub of github.com/labstack/echo/v4 for the rule examples.
package echo

import "net/url"

type Context interface {
	FormValue(name string) string
	FormParams() (url.Values, error)
	Bind(i any) error
}
