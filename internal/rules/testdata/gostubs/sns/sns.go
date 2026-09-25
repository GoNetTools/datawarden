// Package sns is an offline stand-in for github.com/aws/aws-sdk-go-v2/service/sns.
package sns

import "context"

type PublishInput struct {
	Message     *string
	PhoneNumber *string
}

type PublishOutput struct{}

type Options struct{}

type Client struct{}

func (c *Client) Publish(ctx context.Context, params *PublishInput, optFns ...func(*Options)) (*PublishOutput, error) {
	return &PublishOutput{}, nil
}
