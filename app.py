from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash, abort
from flask_sqlalchemy import SQLAlchemy
from models import db, User, PasswordEntry
from config import password_generator
import hasher


app = Flask(__name__)

app.config['SECRET_KEY'] = 'CHANGEZ_ME_en_une_valeur_unique'  # Clé secrète pour les sessions (à changer en production)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///hashiz.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

with app.app_context():
    db.create_all()

KEY_CACHE = {}

@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('home.html')

@app.route('/clinkey')
def clinkey():
    return render_template('clinkey.html')

@app.route('/show_me')
def generate():
    num_char = int(request.args.get('num_char', 16))
    special = request.args.get('special', 'true').lower() == 'true'
    password = password_generator(num_char, special)
    return jsonify({"password": password})

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Route d'inscription d'un nouvel utilisateur."""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm = request.form.get('confirm')
        if not username or not password:
            flash("Please fill up the form.", "warning")
        elif password != confirm:
            flash("Passwords don't match.", "warning")
        elif User.query.filter_by(username=username).first():
            flash("This Username is already in use, please chose another one.", "warning")
        else:
            salt, enc_key, auth_key = hasher.derive_keys(username, password)
            try:
                new_user = User(username=username, salt=salt, password_hash=auth_key)
                db.session.add(new_user)
                db.session.commit()
            except Exception as e:
                flash("An error occurred while registering. Please try again.", "danger")
            else:
                flash("Your account has been created ! You can now sign in.", "success")
                return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user is None:
            flash("Unknown Username.", "danger")
        else:
            if hasher.verify_password(username, password, user.salt, user.password_hash):
                session['user_id'] = user.id
                session['username'] = user.username
                _, enc_key, _ = hasher.derive_keys(username, password, user.salt)
                KEY_CACHE[user.id] = enc_key
                flash(f"Happy to see you back, {user.username} !", "success")
                return redirect(url_for('dashboard'))
            else:
                flash("Wrong password.", "danger")
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Route de déconnexion (terminaison de la session utilisateur)."""
    if 'user_id' in session:
        user_id = session['user_id']
        if user_id in KEY_CACHE:
            KEY_CACHE.pop(user_id)
            session.clear()
        KEY_CACHE.pop(user_id, None)
        session.clear()
        flash("You've been disconnected", "info")
    return redirect(url_for('home'))

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    """Tableau de bord – liste des mots de passe et ajout de nouvelles entrées."""
    if 'user_id' not in session:
        return redirect(url_for('home'))

    user_id = session.get('user_id')
    user = User.query.get(user_id)
    if not user:
        return redirect(url_for('logout'))
    enc_key = KEY_CACHE.get(user_id)

    if not enc_key:
        flash("Your session has expired, please reconnect.", "warning")
        return redirect(url_for('logout'))

    if request.method == 'POST':
        site = request.form.get('site')
        login = request.form.get('login')
        pwd_clear = request.form.get('password')
        if not site or not login or not pwd_clear:
            flash("All the fiels are required.", "warning")
        else:
            try:
                nonce, ciphertext = hasher.encrypt_password(enc_key, pwd_clear)
            except Exception as e:
                flash("Error while crypting the password.", "danger")
            else:
                new_entry = PasswordEntry(user_id=user.id, site=site, login=login,
                                          nonce=nonce, encrypted_password=ciphertext)
                db.session.add(new_entry)
                db.session.commit()
                flash(f"Password saved for '{site}' !.", "success")

    entries = PasswordEntry.query.filter_by(user_id=user.id).all()

    passwords_data = []
    for entry in entries:
        try:
            pwd_plain = hasher.decrypt_password(enc_key, entry.nonce, entry.encrypted_password)
        except Exception as e:
            pwd_plain = "[ERREUR]"
        passwords_data.append({
            'id': entry.id,
            'site': entry.site,
            'login': entry.login,
            'password': pwd_plain
        })
    return render_template('dashboard.html', user=user, passwords=passwords_data)

# app.config['SYNC_ENABLED'] = False
# app.config['API_URL'] = "https://hash-iz.com/api"

if __name__ == '__main__':
    import webbrowser
    webbrowser.open("http://127.0.0.1:5000")
    app.run(host='127.0.0.1', port=5000, debug=True)
