// Package gin is a stub of github.com/gin-gonic/gin for the rule examples.
package gin

type Context struct{}

func (c *Context) PostForm(key string) string                      { return "" }
func (c *Context) DefaultPostForm(key, defaultValue string) string { return "" }
func (c *Context) GetPostForm(key string) (string, bool)           { return "", false }
func (c *Context) PostFormArray(key string) []string               { return nil }
func (c *Context) PostFormMap(key string) map[string]string        { return nil }
func (c *Context) GetRawData() ([]byte, error)                     { return nil, nil }
func (c *Context) Bind(obj any) error                              { return nil }
func (c *Context) BindJSON(obj any) error                          { return nil }
func (c *Context) ShouldBind(obj any) error                        { return nil }
func (c *Context) ShouldBindJSON(obj any) error                    { return nil }
