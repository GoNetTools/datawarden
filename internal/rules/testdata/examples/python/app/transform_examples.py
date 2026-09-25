# Examples for the Python transform rules. A hash is not a safe transform
# by default (phone numbers can be enumerated), so logging it is still a
# violation; encryption is safe.
import base64
import hashlib

import bcrypt
from cryptography.fernet import Fernet


def sha256(phone_number: str):
    # ruleid: xform.py.sha256
    key = hashlib.sha256(phone_number.encode()).hexdigest()
    # ruleid: log.py.print
    print("lookup", key)


def sha512(email: str):
    # ruleid: xform.py.sha512
    key = hashlib.sha512(email.encode()).hexdigest()
    # ruleid: log.py.print
    print("key", key)


def weak_hash(email: str):
    # ruleid: xform.py.weak_hash
    gravatar = hashlib.md5(email.encode()).hexdigest()
    # ruleid: log.py.print
    print("gravatar", gravatar)


def password_hash(email: str):
    # ruleid: xform.py.password_hash
    digest = bcrypt.hashpw(email.encode(), bcrypt.gensalt())
    # ruleid: log.py.print
    print("digest", digest)


def encrypt(email: str, fernet: Fernet):
    # ruleid: xform.py.encrypt
    token = fernet.encrypt(email.encode())
    # ok: log.py.print
    print("sealed", token)


def encode(email: str):
    # ruleid: xform.py.base64
    blob = base64.b64encode(email.encode())
    # ruleid: log.py.print
    print("blob", blob)
