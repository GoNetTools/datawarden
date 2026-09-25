from dataclasses import dataclass


@dataclass
class Shopper:
    shopper_id: str
    email: str
    phone_number: str
    date_of_birth: str
    nickname: str = ""
