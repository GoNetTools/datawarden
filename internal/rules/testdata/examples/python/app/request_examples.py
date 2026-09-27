# Examples for the Python web request sources (internal/rules/builtin/requests.yaml).
import logging

from flask import request

log = logging.getLogger(__name__)


def flask_form():
    # ruleid: src.py.flask_request, log.py.logging
    log.info("signup %s", request.form)
    # ok: src.py.flask_request
    log.info("page %s", request.args.get("page"))
    # ok: src.py.flask_request
    log.info("page %s", request.form["page"])


def flask_json():
    # ruleid: src.py.flask_request
    payload = request.get_json()
    # ruleid: log.py.logging
    log.info("payload %s", payload)


def django_view(request):
    # ruleid: src.py.django_request, log.py.logging
    log.info("posted %s", request.POST)
    # ok: src.py.django_request
    log.info("next %s", request.GET.get("next"))


def drf_view(request):
    # ruleid: src.py.django_request
    data = request.data
    # ruleid: log.py.logging
    log.info("data %s", data)
