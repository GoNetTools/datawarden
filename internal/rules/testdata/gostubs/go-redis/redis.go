// Package redis is an offline stand-in for github.com/redis/go-redis/v9.
package redis

import (
	"context"
	"time"
)

type StatusCmd struct{}

type Client struct{}

func (c *Client) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) *StatusCmd {
	return &StatusCmd{}
}
