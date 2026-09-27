# Examples for the Python SDK rules.
import boto3
import bugsnag
import rollbar
import posthog
import sentry_sdk
from amplitude import Amplitude, BaseEvent
from mixpanel import Mixpanel
from twilio.rest import Client

import analytics

mp = Mixpanel("token")


def sentry(email: str, user_id: str):
    # ruleid: sdk.py.sentry
    sentry_sdk.set_user({"id": user_id, "email": email})
    with sentry_sdk.configure_scope() as scope:
        # ruleid: sdk.py.sentry
        scope.set_extra("email", email)
    # ok: sdk.py.sentry
    sentry_sdk.set_user({"id": user_id})


def segment(user_id: str, email: str):
    # ruleid: sdk.py.segment
    analytics.identify(user_id, {"email": email})
    # ok: sdk.py.segment
    analytics.track(user_id, "signed_up")


def mixpanel(user_id: str, phone: str):
    # ruleid: sdk.py.mixpanel
    mp.people_set(user_id, {"$phone": phone})


def product_analytics(user_id: str, email: str):
    # ruleid: sdk.py.posthog
    posthog.identify(user_id, {"email": email})


def sms(phone_number: str):
    client = Client("sid", "auth")
    # ruleid: sdk.py.twilio
    client.messages.create(to=phone_number, from_="+15550100", body="Your code is 000000")


def sns(phone_number: str):
    sns_client = boto3.client("sns")
    # ruleid: sdk.py.aws_sns
    sns_client.publish(PhoneNumber=phone_number, Message="Your code is 000000")


def rollbar_report(email: str, order_id: str):
    # ruleid: sdk.py.rollbar
    rollbar.report_message("password reset", "info", extra_data={"email": email})
    # ok: sdk.py.rollbar
    rollbar.report_message("order failed", "error", extra_data={"order": order_id})


def bugsnag_notify(error: Exception, email: str, order_id: str):
    # ruleid: sdk.py.bugsnag
    bugsnag.notify(error, user={"email": email})
    # ok: sdk.py.bugsnag
    bugsnag.leave_breadcrumb("checkout", metadata={"order": order_id})


amplitude_client = Amplitude("api-key")


def amplitude_track(user_id: str, phone_number: str):
    # ruleid: sdk.py.amplitude
    amplitude_client.track(BaseEvent(event_type="verified", user_id=user_id, event_properties={"phone": phone_number}))
    # ok: sdk.py.amplitude
    amplitude_client.track(BaseEvent(event_type="opened", user_id=user_id))
