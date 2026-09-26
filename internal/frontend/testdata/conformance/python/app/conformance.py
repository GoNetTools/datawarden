# Frontend conformance programs for Python. Every language implements the
# same scenarios (see TestFrontendConformance in internal/app).
from dataclasses import dataclass


class User:
    def __init__(self, id: int, email: str):
        self.id = id
        self.email = email
        self.contact = ""

    def contact_email(self) -> str:
        return self.email


@dataclass
class Profile:
    email: str
    nickname: str


# scenario: param
def param(email: str):
    # ruleid: log.py.print
    print(email)


# scenario: local
def local(email: str):
    x = email
    # ruleid: log.py.print
    print(x)


# scenario: concat
def concat(email: str):
    msg = f"signup {email}"
    # ruleid: log.py.print
    print(msg)


# scenario: field
def field(u: User):
    # ruleid: log.py.print
    print(u.email)


# scenario: getter
def getter(u: User):
    # ruleid: log.py.print
    print(u.contact_email())


# scenario: key
def key(value: str):
    payload = {"email": value}
    # ruleid: log.py.print
    print(payload)


def log_it(v: str):
    # ruleid: log.py.print
    print(v)


# scenario: call-arg
def call_arg(email: str):
    log_it(email)


def normalize(s: str) -> str:
    return s.strip().lower()


# scenario: call-return
def call_return(email: str):
    # ruleid: log.py.print
    print(normalize(email))


# scenario: closure
def closure(email: str, items: list):
    def each(it):
        # ruleid: log.py.print
        print(it, email)

    for it in items:
        each(it)


# scenario: field-store
def field_store(phone_number: str):
    u = User(1, "")
    u.contact = phone_number
    # ruleid: log.py.print
    print(u.contact)


# scenario: collection
def collection(email: str):
    xs = []
    xs.append(email)
    # ruleid: log.py.print
    print(xs)


# scenario: object
def whole(p: Profile):
    # ruleid: log.py.print
    print(p)


def mask_email(e: str) -> str:
    return e[:1] + "***"


# scenario: masked
def masked(email: str):
    # ok: log.py.print
    print(mask_email(email))


# scenario: not-pii
def not_pii(u: User, order_id: str, count: int):
    # ok: log.py.print
    print(u.id, order_id, count)


# scenario: negative-context
def negative_context(phone_count: int, email_template: str):
    # ok: log.py.print
    print(phone_count, email_template)


# scenario: overwritten
def overwritten(email: str):
    x = email
    x = "anonymous"
    # ok: log.py.print
    print(x)


# scenario: remasked
def remasked(email: str):
    email = mask_email(email)
    # ok: log.py.print
    print(email)


# scenario: branch-merge
def branch_merge(email: str, verbose: bool):
    x = "anonymous"
    if verbose:
        x = email
    # ruleid: log.py.print
    print(x)


# scenario: loop-carried
def loop_carried(email: str, items: list):
    x = "anonymous"
    for _ in items:
        # ruleid: log.py.print
        print(x)
        x = email


# scenario: mutated-later
def mutated_later(email: str):
    xs = []
    # ok: log.py.print
    print(xs)
    xs.append(email)


# scenario: early-return
def early_return(email: str, invalid: bool):
    x = "anonymous"
    if invalid:
        x = email
        # ruleid: log.py.print
        print(x)
        return
    # ok: log.py.print
    print(x)


# scenario: break-exit
def break_exit(email: str, items: list):
    x = "anonymous"
    for item in items:
        if not item:
            x = email
            break
    # ruleid: log.py.print
    print(x)


# scenario: continue-skip
def continue_skip(email: str, items: list):
    for item in items:
        x = "anonymous"
        if not item:
            x = email
            continue
        # ok: log.py.print
        print(x)


# scenario: snapshot
def snapshot(email: str):
    items = []
    msg = f"items={items}"
    items.append(email)
    # ok: log.py.print
    print(msg)


VERBOSE_LOGGING = False


# scenario: constant-condition
def constant_condition(email: str):
    if VERBOSE_LOGGING:
        # ok: log.py.print
        print(email)


# scenario: field-across-methods
class Mailbox:
    def __init__(self, email: str):
        self.addr = email

    def announce(self):
        # ruleid: log.py.print
        print("sending to", self.addr)


def field_across_methods(email: str):
    Mailbox(email).announce()


# scenario: dynamic-dispatch
class Channel:
    def deliver(self, to: str):
        pass


class SmsChannel(Channel):
    def deliver(self, to: str):
        # ruleid: log.py.print
        print("sms", to)


def dynamic_dispatch(c: Channel, email: str):
    c.deliver(email)


# scenario: exception
def exception(email: str):
    try:
        raise ValueError(f"unknown user {email}")
    except ValueError as e:
        # ruleid: log.py.print
        print(e)


# scenario: lambda-variable
def lambda_variable(email: str):
    # ruleid: log.py.print
    show = lambda v: print(v)
    show(email)
