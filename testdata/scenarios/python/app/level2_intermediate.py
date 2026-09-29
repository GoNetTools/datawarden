# Level 2: a value is formatted, stored in an object or a dict, or passed
# to a helper before it reaches a sink.
import json
import logging
from dataclasses import dataclass

import requests
import sentry_sdk

logger = logging.getLogger(__name__)


# S08: health data formatted into a message.
def s08_formatted(patient_id: int, diagnosis: str):
    msg = f"patient {patient_id} diagnosis {diagnosis}"
    # ruleid: log.py.logging
    logger.info(msg)


@dataclass
class PaymentCard:
    holder: str
    card_number: str
    expiry: str


# S09: a field of an object written to a file.
def s09_object_field(card: PaymentCard):
    with open("last-card.json", "w") as fh:
        # ruleid: storage.py.file
        json.dump({"card": card.card_number}, fh)
    with open("last-expiry.json", "w") as fh:
        # ok: storage.py.file
        json.dump({"expiry": card.expiry}, fh)


# S10: a dict key says what its value is.
def s10_dict_key(value: str):
    # ruleid: net.py.http
    requests.post("https://kyc.partner.example/verify", json={"ssn": value})


# audit_log is a helper several scenarios call.
def audit_log(event: str, detail: str):
    # ruleid: log.py.logging
    logger.info("audit %s %s", event, detail)


# S11: the value is logged by a helper.
def s11_helper(email: str):
    audit_log("login", email)


class Patient:
    def __init__(self, patient_id: int, mrn: str):
        self.patient_id = patient_id
        self._mrn = mrn

    def get_mrn(self) -> str:
        return self._mrn


# S12: a getter returns the value.
def s12_getter(patient: Patient):
    # ruleid: sdk.py.sentry
    sentry_sdk.set_user({"id": str(patient.patient_id), "mrn": patient.get_mrn()})


# S13: the value is replaced on one path before it is logged.
def s13_overwritten(email: str, anonymous: bool):
    shown = email
    if anonymous:
        shown = "anonymous"
        # ok: log.py.logging
        logger.info("comment by %s", shown)
        return
    # ruleid: log.py.logging
    logger.info("comment by %s", shown)


# S14: an API key sent to the service it authenticates to.
def s14_credential_to_its_service(api_key: str):
    # ok: net.py.http
    requests.get("https://api.payments.example/v1/balance", headers={"Authorization": f"Bearer {api_key}"})
