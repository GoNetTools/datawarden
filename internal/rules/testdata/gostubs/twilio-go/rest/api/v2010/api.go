// Package openapi is an offline stand-in for github.com/twilio/twilio-go/rest/api/v2010.
package openapi

type CreateMessageParams struct {
	To   *string
	Body *string
}

func (p *CreateMessageParams) SetTo(to string) *CreateMessageParams     { p.To = &to; return p }
func (p *CreateMessageParams) SetBody(body string) *CreateMessageParams { p.Body = &body; return p }

type ApiV2010Message struct{}

type ApiService struct{}

func (c *ApiService) CreateMessage(params *CreateMessageParams) (*ApiV2010Message, error) {
	return &ApiV2010Message{}, nil
}
