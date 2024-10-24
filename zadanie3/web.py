import binascii
import hashlib
import os
from urllib import request

from flask import flash

from flask import Flask, render_template, redirect, url_for
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, EqualTo
from flask_login import login_required, LoginManager, UserMixin, login_user, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
app.config['SECRET_KEY'] = 'upb'

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


common_passwords = [
    "Password123!", "Welcome@2023", "Qwerty#123", "AdminPass!1",
    "LetMeIn@2024", "Secret#Password1", "Summer2023!",
    "Strong@Password7", "My$ecureP@ssword", "1234Test!A",
    "TestPassword#9", "Password1@!", "H@ppyDay2024",
    "ReadMe@2024", "Ch@ngeMeNow1"
]

'''
    Tabulka pre pouzivatelov:
    - id: jedinecne id pouzivatela
    - username: meno pouzivatela

    TODO: tabulku je treba doimplementovat
'''
class User(db.Model, UserMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)  # Heslo bude hashované
    salt = db.Column(db.String(32), nullable=False)  # Nový stĺpec pre salt (v hexadecimálnom formáte)

    def __repr__(self):
        return f'<User {self.username}>'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
    
with app.app_context():
    db.create_all()
    
    # test_user = User(username='test', password='test')
    # db.session.add(test_user)
    # db.session.commit()


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])
    submit = SubmitField('Login')

import re
from wtforms import ValidationError


def hash_password(password: str, salt: bytes = None, iterations: int = 100000) -> (bytes, bytes):
    if salt is None:
        salt = os.urandom(16)  # 16-bytová salt hodnota

    # PBKDF2 s SHA-256 a iteráciami
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        iterations
    )

    return salt, hashed_password

# Funkcia na overenie hesla
def verify_password(stored_password: bytes, stored_salt: bytes, provided_password: str, iterations: int = 100000) -> bool:
    _, hashed_provided_password = hash_password(provided_password, stored_salt, iterations)
    return hashed_provided_password == stored_password

# Funkcia na validáciu hesla
def validate_password_complexity(form, field):
    password = field.data
    if len(password) < 8:
        raise ValidationError('Password must be at least 8 characters long.')
    if not re.search(r'[A-Z]', password):
        raise ValidationError('Password must contain at least one uppercase letter.')
    if not re.search(r'[a-z]', password):
        raise ValidationError('Password must contain at least one lowercase letter.')
    if not re.search(r'[0-9]', password):
        raise ValidationError('Password must contain at least one number.')
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        raise ValidationError('Password must contain at least one special character.')
    if password in password:
        raise ValidationError('Your password is a common password.')


class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired(), validate_password_complexity])
    confirm_password = PasswordField('Confirm Password', validators=[InputRequired(), EqualTo('password')])
    submit = SubmitField('Register')

@app.route('/')
@login_required
def home():
    return render_template('home.html', username=current_user.username)

from werkzeug.security import check_password_hash

import requests
from flask import flash, render_template, redirect, url_for, request  # Make sure to import request
from flask_login import login_user

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        # reCAPTCHA validation
        recaptcha_response = request.form.get('g-recaptcha-response')  # Use parentheses instead of brackets
        secret_key = '6Le4zWkqAAAAAFRKlUlyg9E8DUGBePAfIYA-ldMC'  # Replace with your actual secret key
        payload = {
            'response': recaptcha_response,
            'secret': secret_key
        }

        # Verify the reCAPTCHA response
        response = requests.post('https://www.google.com/recaptcha/api/siteverify', data=payload)
        result = response.json()

        if not result.get('success'):
            flash('Please complete the CAPTCHA.', 'error')
            return render_template('login.html', form=form)

        # Check if the user exists in the database
        user = User.query.filter_by(username=username).first()

        if user:
            # Load stored salt and password hash from the database
            stored_salt = binascii.unhexlify(user.salt)
            stored_password = binascii.unhexlify(user.password)

            # Verify the password using your own function
            if verify_password(stored_password, stored_salt, password):
                # If the password is correct, log in the user
                login_user(user)
                return redirect(url_for('home'))
            else:
                flash("Invalid username or password.", 'error')
        else:
            flash("Invalid username or password.", 'error')

    return render_template('login.html', form=form)


from werkzeug.security import generate_password_hash, check_password_hash


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        # Overenie, či už používateľ existuje
        user_exists = User.query.filter_by(username=username).first()
        if user_exists:
            return render_template('register.html', form=form, message="Username already exists.")

        # Generovanie salt a hashovanie hesla
        salt, hashed_password = hash_password(password)

        # Vytvorenie nového používateľa s uloženým salt a hash heslom
        new_user = User(
            username=username,
            password=binascii.hexlify(hashed_password).decode('utf-8'),
            salt=binascii.hexlify(salt).decode('utf-8')  # Salt uložený v hex formáte
        )

        db.session.add(new_user)
        db.session.commit()

        # Po úspešnej registrácii presmerovať na login
        return redirect(url_for('login'))

    return render_template('register.html', form=form)


@login_required
@app.route('/logout', methods=['POST'])
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(port=1337)