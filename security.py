from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import re
from datetime import datetime
import math
import pyotp
import os

# Wczytywanie bazy częstych haseł z pliku common_passwords.txt
COMMON_PASSWORDS = set()
try:
    current_dir = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(current_dir, "common_passwords.txt")
    if os.path.exists(file_path):
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                pwd = line.strip().lower()
                if pwd:
                    COMMON_PASSWORDS.add(pwd)
    else:
        # Fallback w przypadku braku pliku
        COMMON_PASSWORDS = {"haslo123", "admin123", "password123", "qwerty123", "user123"}
except Exception:
    COMMON_PASSWORDS = {"haslo123", "admin123", "password123", "qwerty123", "user123"}
ph = PasswordHasher(
    time_cost=3,          # Liczba iteracji (zalecane min. 2)
    memory_cost=65536,    # 64 MB RAM (zalecane dla wysokiego bezpieczeństwa)
    parallelism=1,        # Liczba równoległych wątków (dostosuj do procesora)
    hash_len=32,          # Długość wygenerowanego hasza
    salt_len=16,          # Długość soli (16 bajtów to standard bezpieczeństwa)
)


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
    """Sprawdza, czy hasło znajduje się na liście popularnych/niebezpiecznych haseł,
    wykrywając również proste modyfikacje (np. dopisanie znaków specjalnych lub cyfr na końcu)."""
    password_lower = password.strip().lower()
    
    # 1. Dokładne sprawdzenie
    if password_lower in COMMON_PASSWORDS:
        return True
        
    # 2. Sprawdzenie po usunięciu wiodących/kończących znaków specjalnych
    cleaned_specials = re.sub(r'^[^a-zA-Z0-9ąćęłńóśźżĄĆĘŁŃÓŚŹŻ]+|[^a-zA-Z0-9ąćęłńóśźżĄĆĘŁŃÓŚŹŻ]+$', '', password_lower)
    if cleaned_specials in COMMON_PASSWORDS:
        return True
        
    # 3. Sprawdzenie po usunięciu wiodących/kończących znaków specjalnych oraz cyfr
    cleaned_specials_digits = re.sub(r'^[^a-zA-ZąćęłńóśźżĄĆĘŁŃÓŚŹŻ]+|[^a-zA-ZąćęłńóśźżĄĆĘŁŃÓŚŹŻ]+$', '', password_lower)
    if cleaned_specials_digits and cleaned_specials_digits in COMMON_PASSWORDS:
        return True
        
    return False

def generate_totp_secret():
    """Generuje unikalny klucz dla użytkownika (Base32)."""
    return pyotp.random_base32()

def verify_totp_code(secret, code):
    """Weryfikuje czy podany kod jest poprawny dla danego klucza."""
    totp = pyotp.TOTP(secret)
    return totp.verify(code)

def get_totp_uri(secret, username):
    """Generuje URI do kodu QR (opcjonalne, ale bardzo przydatne)."""
    return pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="MojaAplikacja")
