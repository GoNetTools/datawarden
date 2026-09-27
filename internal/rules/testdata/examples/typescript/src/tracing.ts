// Examples for the TypeScript tracing and APM sinks (internal/rules/builtin/typescript.yaml).
import { trace, propagation, Span } from "@opentelemetry/api";
import tracer from "dd-trace";
import newrelic from "newrelic";
import beeline from "honeycomb-beeline";

export function otelSpan(span: Span, email: string, orderId: string) {
  // ruleid: sdk.ts.otel
  span.setAttribute("enduser.id", email);
  // ok: sdk.ts.otel
  span.setAttribute("order.id", orderId);
}

export function otelActiveSpan(phoneNumber: string) {
  // ruleid: sdk.ts.otel
  trace.getActiveSpan()?.addEvent("otp.sent", { phone: phoneNumber });
}

export function otelBaggage(email: string) {
  // ruleid: sdk.ts.otel
  return propagation.createBaggage({ "user.email": { value: email } });
}

export function datadog(userId: string, email: string) {
  const span = tracer.scope().active();
  // ruleid: sdk.ts.datadog.trace
  span?.setTag("user.email", email);
  // ruleid: sdk.ts.datadog.trace
  tracer.setUser({ id: userId, email });
  // ok: sdk.ts.datadog.trace
  span?.setTag("cart.size", 3);
}

export function newRelic(phoneNumber: string) {
  // ruleid: sdk.ts.newrelic
  newrelic.addCustomAttribute("phone", phoneNumber);
  // ok: sdk.ts.newrelic
  newrelic.addCustomAttribute("plan", "pro");
}

export function honeycomb(email: string) {
  // ruleid: sdk.ts.honeycomb
  beeline.addContext({ "user.email": email });
}
