# Language constructs the Python frontend must lower. Unlike the shared
# scenarios in conformance.py, these are specific to Python.
import logging

from . import conformance
from .conformance import Profile

logger = logging.getLogger(__name__)


def audited(fn):
    return fn


class Controller:
    @audited
    def signup(self, email: str):
        # ruleid: log.py.logging
        logger.info("signup %s", email)

    @staticmethod
    def announce(phone: str):
        # ruleid: log.py.logging
        logging.info("sms to %s", phone)

    def forward(self, email: str):
        self.announce(email)


def if_else(email: str, verbose: bool):
    if verbose:
        # ruleid: log.py.print
        print("verbose", email)
    elif email:
        # ok: log.py.print
        print("present")
    else:
        # ok: log.py.print
        print("quiet")


def loops(emails: list):
    for e in emails:
        # ruleid: log.py.print
        print(e)
    for i, (email, _) in enumerate(emails):
        # ruleid: log.py.print
        print(i, email)


def try_except(email: str):
    try:
        conformance.param(email)
    except ValueError as err:
        # ruleid: log.py.logging
        logger.exception("failed for %s: %s", email, err)
    finally:
        # ok: log.py.print
        print("done")


def formatting(email: str, phone: str):
    # ruleid: log.py.print
    print("email %s" % email)
    # ruleid: log.py.print
    print("phone {}".format(phone))
    # ruleid: log.py.print
    print("email: " + email)


def keyword_arguments(value: str):
    # ruleid: log.py.logging
    logger.info("signup", extra={"email": value})


def comprehensions(users: list[Profile]):
    emails = [u.email for u in users]
    # ruleid: log.py.print
    print(emails)
    nicknames = [u.nickname for u in users]
    # ok: log.py.print
    print(nicknames)


def unpacking(profile: Profile):
    email, nickname = profile.email, profile.nickname
    # ruleid: log.py.print
    print(email)


def walrus(p: Profile):
    if (email := p.email) is not None:
        # ruleid: log.py.print
        print(email)


def ternary(p: Profile, use_email: bool):
    contact = p.email if use_email else "anonymous"
    # ruleid: log.py.print
    print(contact)


def with_statement(email: str):
    with open("/tmp/signups.txt", "a") as fh:
        # ruleid: storage.py.file
        fh.write(email)


async def fetch_profile(p: Profile):
    return p


async def async_await(p: Profile):
    profile = await fetch_profile(p)
    # ruleid: log.py.print
    print(profile.email)


def lambdas(emails: list):
    shout = lambda e: e.upper()
    # ruleid: log.py.print
    print(shout(emails[0]))


def splats(*args, **kwargs):
    # ruleid: log.py.print
    print(kwargs["email"])


def dict_access(payload: dict):
    # ruleid: log.py.print
    print(payload["phone_number"])
    # ok: log.py.print
    print(payload["order_id"])


def class_attribute_access(p: Profile):
    data = {"email": p.email}
    data.update(source="web")
    # ruleid: log.py.print
    print(data)
