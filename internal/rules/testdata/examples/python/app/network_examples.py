# Examples for the Python HTTP client rules.
import httpx
import requests


def crm(email: str, order_id: str):
    # ruleid: net.py.http
    requests.post("https://crm.partner.example/leads", json={"email": email})
    # ok: net.py.http
    requests.post("https://crm.partner.example/orders", json={"order": order_id})


async def geo(ip_address: str):
    async with httpx.AsyncClient() as client:
        # ruleid: net.py.http
        await client.get("https://geo.partner.example/lookup", params={"ip": ip_address})


class Enricher:
    def __init__(self):
        self.session = requests.Session()

    def enrich(self, phone: str):
        # ruleid: net.py.http
        self.session.post("https://enrich.partner.example/v1", data={"phone": phone})
