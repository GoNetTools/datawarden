// Examples for the JVM tracing and APM sinks (internal/rules/builtin/jvm.yaml).
package examples;

import com.newrelic.api.agent.NewRelic;
import io.opentelemetry.api.baggage.Baggage;
import io.opentelemetry.api.trace.Span;
import io.opentracing.util.GlobalTracer;

class Tracing {
    void otelSpan(String email, long orderId) {
        Span span = Span.current();
        // ruleid: sdk.otel
        span.setAttribute("enduser.id", email);
        // ok: sdk.otel
        span.setAttribute("order.id", orderId);
    }

    void otelBaggage(String phoneNumber) {
        // ruleid: sdk.otel
        Baggage.current().toBuilder().put("phone", phoneNumber).build().makeCurrent();
    }

    void datadog(String email) {
        io.opentracing.Span span = GlobalTracer.get().activeSpan();
        // ruleid: sdk.datadog.trace
        span.setTag("user.email", email);
        // ok: sdk.datadog.trace
        span.setTag("cart.size", 3);
    }

    void newRelic(String userId, String phoneNumber) {
        // ruleid: sdk.newrelic.agent
        NewRelic.addCustomParameter("phone", phoneNumber);
        // ok: sdk.newrelic.agent
        NewRelic.addCustomParameter("plan", "pro");
    }
}
