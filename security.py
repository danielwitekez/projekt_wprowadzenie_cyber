from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import re


ph = PasswordHasher()


def hash_password(password: str):
    return ph.hash(password)


def verify_password(pw_hash: str, password: str):
    try:
        return ph.verify(pw_hash, password)
    except VerifyMismatchError:
        return False


def validate_password_policy(password: str):
    """
    Podstawowa polityka haseł (OWASP ASVS 4.0):
    - Min 12 znaków
    - Przynajmniej jedna wielka litera, jedna cyfra i znak specjalny
    """
    if len(password) < 12:
        return False, "Hasło musi mieć co najmniej 12 znaków."

    if not re.search(r"[A-Z]", password):
        return False, "Hasło musi zawierać co najmniej jedną wielką literę."

    if not re.search(r"[0-9]", password):
        return False, "Hasło musi zawierać co najmniej jedną cyfrę."

    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Hasło musi zawierać co najmniej jeden znak specjalny."

    return True, "Hasło poprawne."