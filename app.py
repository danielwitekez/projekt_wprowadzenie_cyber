from flask import Flask, request, jsonify
from flask_cors import CORS  # Importuj CORS
from database import db, User
from datetime import datetime, timedelta
from security import verify_password, is_account_locked
from flask import Flask, request, jsonify
from database import db, User
from security import hash_password, validate_password_policy, calculate_entropy, is_password_common
from security import generate_totp_secret, get_totp_uri
from security import verify_totp_code

app = Flask(__name__)
CORS(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

# Tworzenie bazy danych przy pierwszym uruchomieniu
with app.app_context():
    db.create_all()


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    # 1. Podstawowa polityka (długość, znaki)
    is_valid, message = validate_password_policy(password)
    if not is_valid:
        return jsonify({"error": message}), 400

    # 2. Sprawdzenie czy hasło nie jest zbyt popularne (4.0/5.0)
    if is_password_common(password):
        return jsonify({"error": "To hasło jest zbyt popularne. Wybierz coś bardziej unikalnego."}), 400

    # 3. Obliczenie entropii (4.0/5.0)
    entropy = calculate_entropy(password)

    # Przykładowy próg siły: OWASP sugeruje, że > 60 bitów jest OK dla haseł użytkowników
    # Nowe, surowsze progi
    strength = "Słabe"
    if entropy > 100:
        strength = "Mocne"
    elif entropy > 60:
        strength = "Średnie"

    # 4. Sprawdź czy użytkownik istnieje
    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Użytkownik już istnieje"}), 400

    # NOWOŚĆ: Generowanie sekretu TOTP
    user_totp_secret = generate_totp_secret()

    # 5. Haszuj i zapisz
    new_user = User(
        username=username,
        password_hash=hash_password(password),
        totp_secret = user_totp_secret
    )
    db.session.add(new_user)
    db.session.commit()

    return jsonify({
        "message": "Zarejestrowano pomyślnie",
        "totp_secret": user_totp_secret,
        "setup_uri": get_totp_uri(user_totp_secret, username),
        "password_entropy": entropy

    }), 201


from security import verify_totp_code  # dodaj do importów


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    totp_code = data.get('totp_code')  # NOWOŚĆ

    user = User.query.filter_by(username=username).first()

    if not user:
        return jsonify({"error": "Błędny login lub hasło"}), 401

    if is_account_locked(user.lockout_until):
        return jsonify({"error": "Konto zablokowane"}), 403

    # 1. Weryfikacja hasła
    if verify_password(user.password_hash, password):

        # 2. Weryfikacja kodu TOTP (Wymaganie na 5.0)
        if not totp_code or not verify_totp_code(user.totp_secret, totp_code):
            return jsonify({"error": "Błędny lub brakujący kod 2FA (TOTP)"}), 401

        # Sukces
        user.failed_login_attempts = 0
        user.lockout_until = None
        db.session.commit()
        return jsonify({"message": "Logowanie pomyślne (2FA OK!)"}), 200

    else:
        # Porażka (zwiększanie licznika blokady - jak wcześniej)
        user.failed_login_attempts += 1
        # ... (kod blokady z poprzedniego kroku) ...
        db.session.commit()
        return jsonify({"error": "Błędny login lub hasło"}), 401



if __name__ == '__main__':
    app.run(debug=True)