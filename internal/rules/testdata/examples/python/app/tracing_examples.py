# Examples for the Python tracing and APM sinks.
import beeline
import libhoney
import newrelic.agent
from ddtrace import tracer as dd_tracer
from opentelemetry import baggage, trace

tracer = trace.get_tracer(__name__)


def otel_span(email: str, order_id: str):
    with tracer.start_as_current_span("signup") as span:
        # ruleid: sdk.py.otel
        span.set_attribute("user.email", email)
        # ok: sdk.py.otel
        span.set_attribute("order.id", order_id)


def otel_current_span(phone_number: str):
    # ruleid: sdk.py.otel
    trace.get_current_span().add_event("otp.sent", {"phone": phone_number})


def otel_baggage(email: str):
    # ruleid: sdk.py.otel
    return baggage.set_baggage("user.email", email)


def datadog(user_id: str, email: str):
    with dd_tracer.trace("checkout") as span:
        # ruleid: sdk.py.datadog.trace
        span.set_tag("user.email", email)
        # ok: sdk.py.datadog.trace
        span.set_tag("cart.size", 3)


def newrelic_attributes(phone_number: str, user_id: str):
    # ruleid: sdk.py.newrelic
    newrelic.agent.add_custom_attribute("phone", phone_number)
    # ok: sdk.py.newrelic
    newrelic.agent.add_custom_attribute("plan", "pro")


def honeycomb(email: str):
    # ruleid: sdk.py.honeycomb
    beeline.add_context_field("user.email", email)
    ev = libhoney.new_event()
    # ruleid: sdk.py.honeycomb
    ev.add_field("email", email)
    # ok: sdk.py.honeycomb
    ev.add_field("route", "/signup")
