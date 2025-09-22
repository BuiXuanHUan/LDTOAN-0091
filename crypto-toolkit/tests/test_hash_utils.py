import pytest
from securecrypto import hash_utils
from argon2.exceptions import VerifyMismatchError
from argon2 import PasswordHasher

def test_hash_password_and_verify():
    password = "StrongPass123!"
    hashed = hash_utils.hash_password_secure(password)
    ph = PasswordHasher()
    try:
        verified = ph.verify(hashed, password)
    except VerifyMismatchError:
        verified = False
    assert verified == True

def test_wrong_password_verification():
    password = "CorrectPass"
    wrong = "WrongPass"
    hashed = hash_utils.hash_password_secure(password)
    ph = PasswordHasher()
    try:
        verified = ph.verify(hashed, wrong)
    except VerifyMismatchError:
        verified = False
    assert verified == False
