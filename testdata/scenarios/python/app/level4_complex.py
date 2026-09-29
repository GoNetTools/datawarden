# Level 4: dynamic dispatch, callbacks kept in fields, deep objects,
# multi-layer pipelines, device storage and ordering.
import logging
import sqlite3
from dataclasses import dataclass

import requests
from flask import request

logger = logging.getLogger(__name__)


class Notifier:
    def notify(self, to: str, body: str):
        raise NotImplementedError


class SmsNotifier(Notifier):
    def notify(self, to: str, body: str):
        # ruleid: log.py.logging
        logger.info("sms to=%s body=%s", to, body)


class PushNotifier(Notifier):
    def __init__(self):
        self.sent = 0

    def notify(self, to: str, body: str):
        self.sent += 1


# S21: the value reaches the sink through an overridden method.
def s21_dispatch(notifier: Notifier, phone_number: str):
    notifier.notify(phone_number, "your code is ready")


class EventBus:
    def __init__(self):
        self._on_signup = None

    def subscribe(self, handler):
        self._on_signup = handler

    def publish(self, email: str):
        self._on_signup(email)


# S22: a callback kept in a field runs later with the value.
def s22_stored_callback(bus: EventBus, email_address: str):
    def welcome(e):
        # ruleid: log.py.logging
        logger.info("welcome mail queued for %s", e)

    bus.subscribe(welcome)
    bus.publish(email_address)


@dataclass
class Contact:
    home_address: str


@dataclass
class Customer:
    contact: Contact


@dataclass
class Order:
    id: str
    customer: Customer


# S23: a value three fields deep.
def s23_deep_field(order: Order):
    # ruleid: net.py.http
    requests.post("https://shipping.partner.example/labels", data={"to": order.customer.contact.home_address})
    # ok: net.py.http
    requests.post("https://shipping.partner.example/status", data={"order": order.id})


class ProfileRepo:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def save(self, user_id: str, date_of_birth: str):
        cur = self.conn.cursor()
        # ruleid: storage.py.sql
        cur.execute("UPDATE profiles SET dob = ? WHERE id = ?", (date_of_birth, user_id))


class ProfileService:
    def __init__(self, repo: ProfileRepo):
        self.repo = repo

    def update(self, user_id: str, dob: str):
        self.repo.save(user_id, dob)
        # ruleid: net.py.http
        requests.post("https://age-check.partner.example/v1", json={"dob": dob})


# S24: request → service → repository and partner.
def s24_pipeline(svc: ProfileService):
    svc.update(request.form["user_id"], request.form["date_of_birth"])


# S25: a session token persisted on the device.
def s25_device_storage(session_token: str):
    with open(".session", "w") as fh:
        # ruleid: storage.py.file
        fh.write(session_token)


# S26: an object logged before the value is added to it, then after.
def s26_ordering(email: str):
    payload = {"source": "web"}
    # ok: log.py.logging
    logger.info("payload %s", payload)
    payload["email"] = email
    # ruleid: log.py.logging
    logger.info("payload %s", payload)
