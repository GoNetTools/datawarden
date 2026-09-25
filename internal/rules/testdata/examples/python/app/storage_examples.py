# Examples for the Python storage rules. Databases and caches are first
# party: they are reported for the data map, not as violations.
import csv
import json
import sqlite3

import redis


def files(email: str, rows: list):
    with open("/tmp/export.json", "w") as fh:
        # ruleid: storage.py.file
        json.dump({"email": email}, fh)
    with open("/tmp/export.csv", "w") as out:
        writer = csv.writer(out)
        # ruleid: storage.py.file
        writer.writerow([email])


def database(email: str):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    # ruleid: storage.py.sql
    cur.execute("INSERT INTO users (email) VALUES (?)", (email,))


def django_orm(email: str):
    from .models import Customer

    # ruleid: storage.py.sql
    Customer.objects.create(email=email)


def cache(phone: str):
    r = redis.Redis()
    cache = r
    # ruleid: storage.py.redis
    cache.set("otp:last", phone)
