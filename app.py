from datetime import datetime, timedelta
from security import verify_password, is_account_locked
from flask import Flask, request, jsonify
from database import db, User
from security import hash_password, validate_password_policy, calculate_entropy, is_password_common

app = Flask(__name__)
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

    # 5. Haszuj i zapisz
    new_user = User(
        username=username,
        password_hash=hash_password(password)
    )
    db.session.add(new_user)
    db.session.commit()

    return jsonify({
        "message": "Zarejestrowano pomyślnie",
        "password_entropy": entropy,
        "password_strength": strength
    }), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()

    # 1. Sprawdź czy użytkownik istnieje
    if not user:
        return jsonify({"error": "Błędny login lub hasło"}), 401

    # 2. Sprawdź czy konto jest zablokowane (Wymaganie na 4.0/5.0)
    if is_account_locked(user.lockout_until):
        remaining_time = (user.lockout_until - datetime.now()).seconds
        return jsonify({
            "error": f"Konto zablokowane. Spróbuj ponownie za {remaining_time} sekund."
        }), 403

    # 3. Weryfikacja hasła
    if verify_password(user.password_hash, password):
        # Sukces: Resetujemy licznik nieudanych prób
        user.failed_login_attempts = 0
        user.lockout_until = None
        db.session.commit()

        return jsonify({"message": "Logowanie pomyślne!", "user": username}), 200
    else:
        # Porażka: Zwiększamy licznik prób
        user.failed_login_attempts += 1

        # Jeśli przekroczono limit prób (np. 3), blokujemy konto na 5 minut
        if user.failed_login_attempts >= 3:
            user.lockout_until = datetime.now() + timedelta(minutes=5)
            db.session.commit()
            return jsonify({"error": "Zbyt wiele nieudanych prób. Konto zostało zablokowane na 5 minut."}), 403

        db.session.commit()
        return jsonify({"error": "Błędny login lub hasło"}), 401



if __name__ == '__main__':
    app.run(debug=True)