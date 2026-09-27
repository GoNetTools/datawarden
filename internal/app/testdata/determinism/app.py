# Two equally good sources of each data type reach the same sinks: which one
# a scan reports must not depend on the order the analysis meets them in.
import logging

log = logging.getLogger(__name__)


def notify(order):
    log.info("order for %s", order)


def place(checkout, user):
    order = {}
    order["billing"] = checkout.billing_address.first_name
    order["shipping"] = checkout.shipping_address.first_name
    order["contact"] = user.phone_number
    order["backup"] = checkout.phone
    order["ip"] = user.ip_address
    order["ip2"] = checkout.client_ip_address
    notify(order)
    log.info("placed %s", order)


def update(profile, form):
    profile.phone = form.phone
    profile.mobile = form.mobile_number
    profile.email = form.email
    profile.alt = form.contact_email
    notify(profile)
