# Level 3: collections, closures, exceptions, consent checks, sanitizers
# and objects that keep what their constructor was given.
import logging
from dataclasses import dataclass

import analytics

logger = logging.getLogger(__name__)


@dataclass
class Member:
    name: str
    email: str


# S15: a collection built in a loop.
def s15_collection(members: list[Member]):
    emails = []
    for m in members:
        emails.append(m.email)
    # ruleid: log.py.logging
    logger.info("newsletter to %s", ",".join(emails))


# S16: a closure captures the value.
def s16_closure(phone_number: str, codes: list[str]):
    def send(code: str):
        # ruleid: log.py.logging
        logger.info("sms %s %s", phone_number, code)

    for c in codes:
        send(c)


class AccountNotFound(Exception):
    pass


def lookup_account(email: str):
    raise AccountNotFound(f"no account for {email}")


# S17: the value travels in an exception.
def s17_exception(email: str):
    try:
        lookup_account(email)
    except AccountNotFound as err:
        # ruleid: log.py.logging
        logger.warning("lookup failed: %s", err)


# S18: analytics sent only after a consent check. Reported with the check;
# accepted when policy.consent_guarded lists third_party.
def s18_consent_guarded(user_id: str, email: str, consents):
    if not consents.has_analytics_consent():
        return
    # ruleid: sdk.py.segment
    analytics.identify(user_id, {"email": email})


def is_masked(value: str) -> bool:
    return "***" in value


# S19: logged only when a check says it is already masked.
def s19_sanitizer(email: str):
    if is_masked(email):
        # ok: log.py.logging
        logger.info("contact %s", email)


class Session:
    def __init__(self, user_id: str, token: str):
        self.user_id = user_id
        self.access_token = token

    # S20: the constructor stores the value, another method logs it.
    def debug(self):
        # ruleid: log.py.logging
        logger.info("session user=%s token=%s", self.user_id, self.access_token)


def s20_constructor_field(user_id: str, token: str):
    Session(user_id, token).debug()
