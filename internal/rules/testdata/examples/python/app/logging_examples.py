# Examples for the Python logging rules.
import logging
import sys

import structlog
from loguru import logger as loguru_logger

log = logging.getLogger(__name__)


class SignupService:
    def __init__(self):
        self._logger = logging.getLogger("signup")

    def register(self, email: str):
        # ruleid: log.py.logging
        self._logger.info("registered %s", email)


def stdlib(email: str, order_id: str):
    # ruleid: log.py.print
    print("signup", email)
    # ruleid: log.py.print
    sys.stderr.write(email)
    # ok: log.py.print
    print("order", order_id)


def logging_module(phone: str):
    # ruleid: log.py.logging
    logging.warning("otp sent to %s", phone)
    # ruleid: log.py.logging
    log.info("otp sent to %s", phone)
    # ruleid: log.py.logging
    logging.getLogger(__name__).error("otp failed for %s", phone)


def third_party_loggers(email: str):
    # ruleid: log.py.logging
    structlog.get_logger().info("signup", email=email)
    # ruleid: log.py.logging
    loguru_logger.info("signup {}", email)
