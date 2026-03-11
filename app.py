from flask import Flask, render_template, url_for, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv
import os

load_dotenv()

app = Flask(__name__)
# Hash passwords
bcrypt = Bcrypt(app)

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
db = SQLAlchemy(app)

# Login Managers
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Reload User object from user id stored in session.
@login_manager.user_loader
def load_user(user_id):
  return User.query.get(int(user_id))

# User Table
class User(db.Model, UserMixin):
  id = db.Column(db.Integer, primary_key=True)
  username = db.Column(db.String(30), nullable=False, unique=True)
  password = db.Column(db.String(50), nullable=False)
  is_admin = db.Column(db.Boolean, default=False)

# Registration Form that inherits from Flask Form
class RegisterForm(FlaskForm):
  username = StringField(validators=[InputRequired(), Length(
    min=4, max=30
  )], render_kw={"placeholder": "Username"})

  password = PasswordField(validators=[InputRequired(), Length(
    min=4, max=50
  )], render_kw={"placeholder": "Password"})

  submit = SubmitField("Register")

  # Validates we have a unique username
  def validate_username(self, username):
    # Queries database and checks if username exists.
    existing_username = User.query.filter_by(
      username=username.data).first()
    if existing_username:
      raise ValidationError(
        "That username already exists! Please choose a different one."
      )
    
# Login Form that inherits from Flask Form
class LoginForm(FlaskForm):
  username = StringField(validators=[InputRequired(), Length(
    min=4, max=30
  )], render_kw={"placeholder": "Username"})

  password = PasswordField(validators=[InputRequired(), Length(
    min=4, max=50
  )], render_kw={"placeholder": "Password"})

  submit = SubmitField("Login")


@app.route('/')
def home():
  return render_template('home.html')

# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
  form = LoginForm()
  if form.validate_on_submit():
    user = User.query.filter_by(username=form.username.data).first()
    if user:
      if bcrypt.check_password_hash(user.password, form.password.data):
        login_user(user)
        return redirect(url_for('dashboard'))
  return render_template('login.html', form=form)

# Dashboard Route
@app.route('/dashboard', methods=['GET', 'POST'])
# Only access dashboard if logged in.
@login_required
def dashboard():
  return render_template('dashboard.html')

# Logout Route
@app.route('/logout', methods=['GET', 'POST'])
# Only logout if logged in.
@login_required
def logout():
  logout_user()
  return redirect(url_for('login'))

# Register Route
@app.route('/register', methods=['GET', 'POST'])
def register():
  form = RegisterForm()

  if form.validate_on_submit():
    hashed_password = bcrypt.generate_password_hash(form.password.data)
    new_user = User(username=form.username.data, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return redirect(url_for('login'))

  return render_template('register.html', form=form)
  
# Runs apps and catches any errors.
if __name__=='__main__':
  app.run(debug=True)
