from flask_sqlalchemy import SQLAlchemy


db = SQLAlchemy()


class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)

    salt = db.Column(db.LargeBinary(16), nullable=False)
    password_hash = db.Column(db.LargeBinary(32), nullable=False)

    passwords = db.relationship('PasswordEntry', backref='user', lazy=True)

    def __repr__(self):
        return f"<User {self.username}>"


class PasswordEntry(db.Model):
    __tablename__ = 'password_entry'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    site = db.Column(db.String(100), nullable=False)
    login = db.Column(db.String(220), nullable=False)

    nonce = db.Column(db.LargeBinary(12), nullable=False)
    encrypted_password = db.Column(db.LargeBinary, nullable=False)

    def __repr__(self):
        return f"<PasswordEntry {self.site} ({self.login})>"
