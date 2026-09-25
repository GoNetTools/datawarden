// Package twilio is an offline stand-in for github.com/twilio/twilio-go.
package twilio

import openapi "github.com/twilio/twilio-go/rest/api/v2010"

type RestClient struct {
	Api *openapi.ApiService
}

func NewRestClient() *RestClient { return &RestClient{Api: &openapi.ApiService{}} }
