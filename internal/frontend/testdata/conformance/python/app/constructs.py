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


def subscript_store(value: str):
    payload = {}
    payload["email"] = value
    # ruleid: log.py.print
    print(payload)


class Card:
    holder = ""


def attribute_store(email: str):
    card = Card()
    card.holder = email
    # ruleid: log.py.print
    print(card.holder)


def starred(emails: list):
    first, *rest = emails
    # ruleid: log.py.print
    print(first)


def annotated(email: str):
    contact: str = email
    later: str
    # ruleid: log.py.print
    print(contact)


def augmented(email: str):
    msg = "to: "
    msg += email
    # ruleid: log.py.print
    print(msg)


def generator_argument(emails: list):
    # ruleid: log.py.print
    print(", ".join(e for e in emails))


def dict_comprehension(profiles: list[Profile]):
    by_mail = {p.email: p.nickname for p in profiles}
    # ruleid: log.py.print
    print(by_mail)


def static_call(phone: str):
    Controller.announce(phone)


def boolean_ops(email: str, fallback: str):
    contact = email or fallback
    # ruleid: log.py.print
    print(contact)
    # ok: log.py.print
    print(email is None, not email)


def raise_with(email: str):
    # ok: log.py.print
    print("validating")
    assert email, "missing"
    raise ValueError(email)


def elif_overwrites(email: str, kind: int):
    x = email
    if kind == 1:
        x = "one"
    elif kind == 2:
        x = "two"
    else:
        x = "other"
    # ok: log.py.print
    print(x)


def match_overwrites(email: str, kind: int):
    x = email
    match kind:
        case 1:
            x = "one"
        case _:
            x = "other"
    # ok: log.py.print
    print(x)


def except_sees_earlier_value(email: str):
    x = email
    try:
        x = "cleared"
        int(x)
    except ValueError:
        # ruleid: log.py.print
        print(x)


def augmented(email: str):
    x = "user "
    x += email
    # ruleid: log.py.print
    print(x)
