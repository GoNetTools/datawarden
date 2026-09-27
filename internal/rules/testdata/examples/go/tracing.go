// Examples for the Go tracing and APM sinks (internal/rules/builtin/go.yaml).
package examples

import (
	"context"

	beeline "github.com/honeycombio/beeline-go"
	libhoney "github.com/honeycombio/libhoney-go"
	"github.com/newrelic/go-agent/v3/newrelic"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/baggage"
	otellog "go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/trace"
	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace/tracer"
)

func otelSpan(ctx context.Context, email string, orderID int) {
	span := trace.SpanFromContext(ctx)
	// ruleid: sdk.go.otel
	span.SetAttributes(attribute.String("user.email", email))
	// ok: sdk.go.otel
	span.SetAttributes(attribute.Int("order.id", orderID))
	// ruleid: sdk.go.otel
	span.AddEvent("otp.sent", trace.WithAttributes(attribute.String("phone", phoneOf(ctx))))
}

func phoneOf(ctx context.Context) (phoneNumber string) { return }

func otelBaggage(ctx context.Context, email string) context.Context {
	// ruleid: sdk.go.otel
	m, _ := baggage.NewMember("user.email", email)
	b, _ := baggage.New(m)
	return baggage.ContextWithBaggage(ctx, b)
}

func otelLogRecord(ctx context.Context, logger otellog.Logger, nationalID string) {
	var r otellog.Record
	// ruleid: sdk.go.otel
	r.SetBody(otellog.StringValue("id check failed for " + nationalID))
	logger.Emit(ctx, r)
}

func datadogTrace(ctx context.Context, userID, email string) {
	span, _ := tracer.SpanFromContext(ctx)
	// ruleid: sdk.go.datadog.trace
	span.SetTag("user.email", email)
	// ruleid: sdk.go.datadog.trace
	tracer.SetUser(span, userID, tracer.WithUserEmail(email))
	// ok: sdk.go.datadog.trace
	span.SetTag("cart.size", 3)
}

func newRelic(ctx context.Context, app *newrelic.Application, phoneNumber string) {
	txn := newrelic.FromContext(ctx)
	// ruleid: sdk.go.newrelic
	txn.AddAttribute("phone", phoneNumber)
	// ruleid: sdk.go.newrelic
	app.RecordCustomEvent("OtpSent", map[string]interface{}{"phone": phoneNumber})
	// ok: sdk.go.newrelic
	txn.AddAttribute("plan", "pro")
}

func honeycomb(ctx context.Context, email string) {
	ev := libhoney.NewEvent()
	// ruleid: sdk.go.honeycomb
	ev.AddField("user.email", email)
	// ok: sdk.go.honeycomb
	ev.AddField("route", "/signup")
	// ruleid: sdk.go.honeycomb
	beeline.AddField(ctx, "email", email)
}
