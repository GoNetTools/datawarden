# The recommender service of vulnshop (Flask). Vulnerable by design: every
# "LEAK" comment marks personal data reaching a place it should not, and
# every "SAFE" comment marks a look-alike a scanner must not report.
import logging

import requests
import sentry_sdk
from flask import Flask, jsonify, request

from .models import Shopper
from .store import save_profile

app = Flask(__name__)
log = logging.getLogger(__name__)


@app.post("/recommendations")
def recommendations():
    body = request.get_json()
    shopper = Shopper(**body["shopper"])
    # LEAK: email to the application log.
    log.info("recommendations for %s", shopper.email)
    # LEAK: phone number to Sentry as extra context.
    sentry_sdk.set_extra("phone", shopper.phone_number)
    # LEAK: date of birth sent to an ad-tech partner.
    requests.post("https://ads.partner.example/segments", json={"dob": shopper.date_of_birth, "sku": body["sku"]})
    # SAFE: the shopper id and a product only.
    log.info("recommend sku=%s for %s", body["sku"], shopper.shopper_id)
    # SAFE: masked before logging.
    log.info("mail to %s", mask_email(shopper.email))
    # SAFE: the nickname is public profile text.
    log.info("hello %s", shopper.nickname)
    save_profile(shopper)
    return jsonify(items=[])


@app.post("/login")
def login():
    email = request.form["email"]
    password = request.form["password"]
    debug_attempt(email, password)
    return jsonify(ok=False), 401


@app.post("/feedback")
def feedback():
    # LEAK: the whole submitted form, contact details included, in the log.
    log.info("feedback %s", request.form)
    # SAFE: one query parameter, named for what it is.
    log.info("from page %s", request.args.get("page"))
    return jsonify(ok=True)


def debug_attempt(user, secret_password):
    # LEAK: email and password printed by a debugging helper.
    print(f"login attempt {user}:{secret_password}")


def mask_email(email: str) -> str:
    return email[:1] + "***"
