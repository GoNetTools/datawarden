# Level 1: a value reaches a sink in the function it arrives in.
import hashlib
import logging

logger = logging.getLogger(__name__)


# S01: a parameter logged as it arrives.
def s01_direct_param(email: str):
    # ruleid: log.py.logging
    logger.info("signup %s", email)


# S02: a local variable named for what it holds.
def s02_local_variable(raw: str):
    phone_number = raw.strip()
    # ruleid: log.py.logging
    logger.info("otp sent to %s", phone_number)


# S03: values that are not personal data, and names that only look like it.
def s03_not_personal(order_id: str, item_count: int, email_enabled: bool, phone_formatter: str):
    # ok: log.py.logging
    logger.info("order %s items %d", order_id, item_count)
    # ok: log.py.logging
    logger.info("email notifications %s", email_enabled)
    # ok: log.py.logging
    logger.info("format %s", phone_formatter)


# S04: a credential logged.
def s04_credential(username: str, password: str):
    # ruleid: log.py.logging
    logger.info("login %s/%s", username, password)


def mask_email(email: str) -> str:
    name, _, domain = email.partition("@")
    return name[:1] + "***@" + domain


# S05: masked before it is logged.
def s05_masked(email: str):
    # ok: log.py.logging
    logger.info("reset link sent to %s", mask_email(email))


# S06: a hash of personal data still identifies the person.
def s06_hashed_personal(email: str):
    digest = hashlib.sha256(email.encode()).hexdigest()
    # ruleid: log.py.logging
    logger.info("lookup key %s", digest)


# S07: a hashed password is safe to log.
def s07_hashed_credential(password: str):
    digest = hashlib.sha256(password.encode()).hexdigest()
    # ok: log.py.logging
    logger.info("password fingerprint %s", digest)
