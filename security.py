from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import re
from datetime import datetime
import math


# Lista 10 najpopularniejszych haseł (dla przykładu - w realnym systemie warto mieć plik .txt z 10 000 haseł)
COMMON_PASSWORDS = ["Haslo123", "Admin123", "Password123", "Qwerty123", "User123"]
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

def is_account_locked(lockout_until):
    """Sprawdza, czy konto jest obecnie zablokowane."""
    if lockout_until and datetime.now() < lockout_until:
        return True
    return False


def calculate_entropy(password: str) -> float:
    """
    Oblicza entropię hasła w bitach.
    E = L * log2(R)
    """
    if not password:
        return 0

    pool_size = 0
    # Sprawdzanie zestawów znaków
    if any(c.islower() for c in password):
        pool_size += 26
    if any(c.isupper() for c in password):
        pool_size += 26
    if any(c.isdigit() for c in password):
        pool_size += 10
    # POPRAWIONE: Sprawdzanie czy istnieją znaki, które nie są alfanumeryczne
    if any(not c.isalnum() for c in password):
        pool_size += 32

    if pool_size == 0:
        return 0

    entropy = len(password) * math.log2(pool_size)
    return round(entropy, 2)


def is_password_common(password: str) -> bool:
    """Sprawdza, czy hasło jest na czarnej liście lub zaczyna się od popularnego wzorca."""
    password_lower = password.lower()
    for common in COMMON_PASSWORDS:
        if common.lower() in password_lower: # Sprawdza czy np. "haslo" jest częścią hasła
            return True
    return False