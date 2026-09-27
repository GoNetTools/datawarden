// Examples for the Swift tracing and APM sinks (internal/rules/builtin/swift.yaml).
import DatadogTrace
import NewRelic
import OpenTelemetryApi

func otelSpan(tracer: Tracer, email: String, orderId: Int) {
    let span = tracer.spanBuilder(spanName: "signup").startSpan()
    // ruleid: sdk.swift.otel
    span.setAttribute(key: "enduser.id", value: email)
    // ok: sdk.swift.otel
    span.setAttribute(key: "order.id", value: orderId)
    span.end()
}

func datadogSpan(email: String) {
    let span = Tracer.shared().startSpan(operationName: "checkout")
    // ruleid: sdk.swift.datadog.trace
    span.setTag(key: "user.email", value: email)
    // ok: sdk.swift.datadog.trace
    span.setTag(key: "cart.size", value: 3)
    span.finish()
}

func newRelic(phoneNumber: String) {
    // ruleid: sdk.swift.newrelic
    NewRelic.setAttribute("phone", value: phoneNumber)
    // ok: sdk.swift.newrelic
    NewRelic.setAttribute("plan", value: "pro")
}
