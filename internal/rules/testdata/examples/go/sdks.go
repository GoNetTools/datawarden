// Examples for the Go third-party SDK sinks.
package examples

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/getsentry/sentry-go"
	"github.com/segmentio/analytics-go/v3"
	"github.com/twilio/twilio-go"
	openapi "github.com/twilio/twilio-go/rest/api/v2010"
)

func sentryScope(email string) {
	sentry.ConfigureScope(func(scope *sentry.Scope) {
		// ruleid: sdk.go.sentry.scope
		scope.SetUser(sentry.User{Email: email})
		// ruleid: sdk.go.sentry.scope_kv
		scope.SetExtra("contact", email)
		// ok: sdk.go.sentry.scope_kv
		scope.SetTag("plan", "pro")
	})
}

func segmentTrack(client analytics.Client, email string) {
	// ruleid: sdk.go.segment
	_ = client.Enqueue(analytics.Track{Event: "signup", Properties: analytics.NewProperties().Set("email", email)})
}

func twilioSMS(phoneNumber string) {
	client := twilio.NewRestClient()
	params := &openapi.CreateMessageParams{}
	params.SetTo(phoneNumber)
	// ruleid: sdk.go.twilio.sms
	_, _ = client.Api.CreateMessage(params)
}

func snsPublish(ctx context.Context, c *sns.Client, phoneNumber string) {
	msg := "Your code is 123456"
	// ruleid: sdk.go.aws.sns
	_, _ = c.Publish(ctx, &sns.PublishInput{PhoneNumber: &phoneNumber, Message: &msg})
}
