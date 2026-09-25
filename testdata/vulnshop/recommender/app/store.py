import pickle
import sqlite3


def save_profile(shopper):
    conn = sqlite3.connect("recommender.db")
    # SAFE: our own database is the purpose (first party).
    conn.execute("INSERT INTO profiles VALUES (?, ?)", (shopper.shopper_id, shopper.email))
    # LEAK: the whole profile pickled into a world-readable file.
    with open("/tmp/profiles.pkl", "ab") as fh:
        pickle.dump(shopper, fh)
