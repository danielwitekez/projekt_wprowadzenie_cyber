# Secure Auth System with 2FA & Argon2

Nowoczesny, bezpieczny system uwierzytelniania użytkowników oparty na architekturze klient-serwer. Projekt został zrealizowany z naciskiem na najlepsze praktyki cyberbezpieczeństwa (zgodne z zaleceniami **OWASP ASVS 4.0**).

Aplikacja składa się z backendu napisanego w języku **Python (Flask)** oraz nowoczesnego frontendu w bibliotece **React (Vite)**.

---

## 🚀 Główne Funkcjonalności

*   **Bezpieczne haszowanie haseł (Argon2id):** Wykorzystanie wiodącego algorytmu szyfrowania hasha `Argon2` (zwycięzcy Password Hashing Competition) zoptymalizowanego pod kątem odporności na ataki GPU/ASIC (time cost = 3, memory cost = 64MB).
*   **Dwuetapowa weryfikacja (2FA / TOTP):** Generowanie unikalnego klucza (base32) przy rejestracji, prezentacja kodu QR ułatwiającego parowanie z aplikacjami uwierzytelniającymi (np. *Google Authenticator*, *Microsoft Authenticator*) oraz weryfikacja kodów jednorazowych przy logowaniu.
*   **Dynamiczna analiza entropii hasła:** Obliczanie i prezentowanie siły hasła (w bitach entropii) w czasie rzeczywistym na frontendzie przed rejestracją.
*   **Rygorystyczna polityka haseł (OWASP):** Weryfikacja minimalnej długości (12 znaków), zestawów znaków (wielka litera, cyfra, znak specjalny) oraz ochrona przed popularnymi hasłami (czarna lista słabych haseł, np. `Admin123`).
*   **Zabezpieczenie przed brute-force (Lockout):** Przygotowana struktura bazy danych i logiki pod czasowe blokowanie konta po określonej liczbie nieudanych prób logowania.
*   **Obsługa Case-Insensitivity:** Logowanie i rejestracja ignorują wielkość liter w nazwach użytkowników, co zapobiega dublowaniu kont i poprawia wrażenia użytkownika (UX).

---

## 🛠️ Stos Technologiczny

### Backend (API)
*   **Język:** Python 3.x
*   **Framework:** Flask (z obsługą CORS)
*   **Baza danych:** SQLite
*   **ORM:** Flask-SQLAlchemy
*   **Bezpieczeństwo:** `argon2-cffi` (haszowanie haseł), `pyotp` (obsługa algorytmu TOTP)

### Frontend (Klient)
*   **Technologia:** React.js (Vite)
*   **Stylizacja:** Vanilla CSS (nowoczesny, responsywny design typu *card component*)
*   **Komunikacja:** Axios (asynchroniczne zapytania HTTP)
*   **Ikony:** Lucide React

---

## 📁 Struktura Projektu

```text
projekt_wprowadzenie_cyber/
│
├── app.py                 # Główny plik serwera Flask (endpointy /register i /login)
├── database.py            # Definicja modelu bazy danych (User) za pomocą SQLAlchemy
├── security.py            # Logika bezpieczeństwa (haszowanie Argon2, entropia, walidacja polityki, TOTP)
├── instance/              # Folder zawierający lokalną bazę danych SQLite (users.db)
│
└── frontend/              # Aplikacja kliencka React
    ├── src/
    │   ├── App.jsx        # Główny komponent z formularzem logowania, rejestracji i weryfikacji 2FA
    │   └── main.jsx       # Punkt wejścia aplikacji React
    ├── package.json       # Zależności i skrypty npm dla frontendu
    └── vite.config.js     # Konfiguracja serwera deweloperskiego Vite
```

---

## 💻 Jak Uruchomić Projekt Lokalnie

### Wymagania wstępne
*   Zainstalowany Python (wersja 3.8 lub nowsza)
*   Zainstalowane środowisko Node.js (wersja 18 lub nowsza) wraz z menedżerem pakietów `npm`

---

### Krok 1: Uruchomienie Backend-u

1. Otwórz terminal w głównym katalogu projektu (`projekt_wprowadzenie_cyber/`).
2. Zainstaluj wymagane pakiety Pythona:
   ```bash
   pip install flask flask-cors flask-sqlalchemy argon2-cffi pyotp
   ```
3. Uruchom serwer Flask:
   ```bash
   python app.py
   ```
   Serwer powinien uruchomić się na porcie `http://127.0.0.1:5000`.

---

### Krok 2: Uruchomienie Frontend-u

1. Otwórz drugie okno terminala i przejdź do katalogu frontendu:
   ```bash
   cd frontend
   ```
2. Zainstaluj zależności Node.js:
   ```bash
   npm install
   ```
3. Uruchom aplikację w trybie deweloperskim:
   ```bash
   npm run dev
   ```
   *(Jeśli na systemie Windows system blokuje uruchamianie skryptów PowerShell, użyj komendy: `npm.cmd run dev`)*
4. Kliknij w wygenerowany w terminalu link (zazwyczaj `http://localhost:5173`), aby otworzyć aplikację w przeglądarce.

---

## 🛡️ Przykładowe Dane do Testów

Jeśli chcesz przetestować aplikację bez zakładania nowego konta, w bazie danych domyślnie przygotowany jest profil testowy:
*   **Nazwa użytkownika:** `User1`
*   **Hasło:** `CyberPro123!@#`
*   **Klucz TOTP (do ręcznego przepisania w Google Authenticator):** `2XCM35KDLZC2GNUIRIM3VXO4NT7VGK4L`
