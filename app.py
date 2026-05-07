from flask import Flask, request, jsonify
from database import db, User
from security import hash_password, validate_password_policy, verify_password

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

    # 1. Sprawdź politykę haseł
    is_valid, message = validate_password_policy(password)
    if not is_valid:
        return jsonify({"error": message}), 400

    # 2. Sprawdź czy użytkownik istnieje
    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Użytkownik już istnieje"}), 400

    # 3. Haszuj i zapisz
    new_user = User(
        username=username,
        password_hash=hash_password(password)
    )
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "Zarejestrowano pomyślnie"}), 201

if __name__ == '__main__':
    app.run(debug=True)