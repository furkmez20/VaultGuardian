
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from flask_mail import Mail
from wtforms import StringField, PasswordField, TextAreaField, HiddenField

import os
import json
from dotenv import load_dotenv
from wtforms.validators import DataRequired, Length, Email, EqualTo

from .forms import MFAForm  # or wherever you define it

from .models import JSONDataStore, Credential
from .auth import AuthManager
from .crypto import CryptoManager
from .mfa import MFAManager

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-key-change-in-production')
app.config['WTF_CSRF_ENABLED'] = True

# Mail configuration
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True').lower() == 'true'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_USERNAME')

# Initialize extensions
csrf = CSRFProtect(app)
mail = Mail(app)

# Initialize managers
data_store = JSONDataStore()
auth_manager = AuthManager(data_store)
mfa_manager = MFAManager(mail)

# Forms
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=50)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=50)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField(
        'Confirm Password',
        validators=[DataRequired(), EqualTo('password', message='Passwords must match')]
    )
    email = StringField('Email', validators=[Email()])

class MFAForm(FlaskForm):
    otp_code = StringField('OTP Code', validators=[DataRequired(), Length(min=6, max=6)])

class CredentialForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(min=1, max=100)])
    username = StringField('Username')
    password = PasswordField('Password')
    url = StringField('URL')
    notes = TextAreaField('Notes')
    credential_id = HiddenField()

@app.route('/')
def index():
    if 'username' in session and session.get('mfa_verified'):
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        email = form.email.data
        
        # Generate MFA secret
        mfa_secret = mfa_manager.generate_secret()
        
        if auth_manager.register_user(username, password, mfa_secret, email):
            flash('Registration successful! Please set up MFA.', 'success')
            session['username'] = username
            session['setup_mfa'] = True
            return redirect(url_for('setup_mfa'))
        else:
            flash('Username already exists.', 'error')
    
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        
        if auth_manager.is_user_locked(username):
            flash('Account is temporarily locked due to too many failed attempts.', 'error')
            return render_template('login.html', form=form)
        
        user = auth_manager.authenticate_user(username, password)
        if user:
            session['username'] = username
            session['mfa_verified'] = False
            return redirect(url_for('mfa_verify'))
        else:
            flash('Invalid username or password.', 'error')
    
    return render_template('login.html', form=form)



@app.route('/setup_mfa', methods=['GET', 'POST'])
def setup_mfa():
    if 'username' not in session or not session.get('setup_mfa'):
        return redirect(url_for('login'))

    username = session['username']
    user = data_store.get_user(username)
    form = MFAForm()

    qr_code = mfa_manager.generate_qr_code(username, user.mfa_secret)

    if form.validate_on_submit():
        otp_input = form.otp_code.data
        if mfa_manager.verify_totp(user.mfa_secret, otp_input):
            session['mfa_verified'] = True
            session.pop('setup_mfa', None)
            flash("MFA setup complete!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid code. Try again.", "error")

    return render_template('setup_mfa.html', qr_code=qr_code, secret=user.mfa_secret, form=form, user=user, is_setup=True)


#@app.route('/setup_mfa', methods=['GET', 'POST'])
@app.route('/mfa', methods=['GET', 'POST'])
def mfa_verify():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    username = session['username']
    user = data_store.get_user(username)
    form = MFAForm()
    
    if form.validate_on_submit():
        otp_code = form.otp_code.data
        
        # Try TOTP first
        if mfa_manager.verify_totp(user.mfa_secret, otp_code):
            session['mfa_verified'] = True
            #session.pop('setup_mfa', None)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        # Try email OTP if user has email
        elif user.email and mfa_manager.verify_email_otp(user.email, otp_code):
            session['mfa_verified'] = True
            #session.pop('setup_mfa', None)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid OTP code.', 'error')
    
    return render_template('setup_mfa.html', form=form, user=user, is_setup=False)

@app.route('/send_email_otp', methods=['POST'])
def send_email_otp():
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Not logged in'})
    
    user = data_store.get_user(session['username'])
    if user and user.email:
        if mfa_manager.send_email_otp(user.email):
            return jsonify({'success': True, 'message': 'OTP sent to email'})
    
    return jsonify({'success': False, 'message': 'Failed to send OTP'})

@app.route('/dashboard')
def dashboard():
    if 'username' not in session or not session.get('mfa_verified'):
        return redirect(url_for('login'))
    
    username = session['username']
    credentials = data_store.get_credentials(username)

    form = CredentialForm()
    user = data_store.get_user(username) 
    
    return render_template('dashboard.html', credentials=credentials, form=form, user=user)

@app.route('/add_credential', methods=['GET', 'POST'])
def add_credential():
    if 'username' not in session or not session.get('mfa_verified'):
        return redirect(url_for('login'))
    
    form = CredentialForm()
    if form.validate_on_submit():
        username = session['username']
        
        # Create credential data
        cred_data = {
            'username': form.username.data,
            'password': form.password.data,
            'url': form.url.data,
            'notes': form.notes.data
        }
        
        # Encrypt credential data
        user = data_store.get_user(username)
        crypto = CryptoManager()
        encrypted_data = crypto.encrypt_data(json.dumps(cred_data), None)
        
        # Create and save credential
        credential = Credential(
            title=form.title.data,
            encrypted_data=encrypted_data,
            id=form.credential_id.data if form.credential_id.data else None
        )
        
        if data_store.save_credential(username, credential):
            flash('Credential saved successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Failed to save credential.', 'error')
    
    return render_template('add_credential.html', form=form)

@app.route('/edit_credential/<credential_id>', methods=['GET', 'POST'])
def edit_credential(credential_id):
    if 'username' not in session or not session.get('mfa_verified'):
        return redirect(url_for('login'))
    
    username = session['username']
    credentials = data_store.get_credentials(username)
    credential = next((c for c in credentials if c.id == credential_id), None)
    
    if not credential:
        flash('Credential not found.', 'error')
        return redirect(url_for('dashboard'))
    
    form = CredentialForm()
    
    if request.method == 'GET':
        # Decrypt and populate form
        try:
            crypto = CryptoManager()
            decrypted_data = crypto.decrypt_data(credential.encrypted_data)
            cred_data = json.loads(decrypted_data)
            
            form.title.data = credential.title
            form.username.data = cred_data.get('username', '')
            form.password.data = cred_data.get('password', '')
            form.url.data = cred_data.get('url', '')
            form.notes.data = cred_data.get('notes', '')
            form.credential_id.data = credential_id
        except Exception:
            flash('Failed to decrypt credential.', 'error')
            return redirect(url_for('dashboard'))
    
    if form.validate_on_submit():
        # Update credential
        cred_data = {
            'username': form.username.data,
            'password': form.password.data,
            'url': form.url.data,
            'notes': form.notes.data
        }
        
        crypto = CryptoManager()
        encrypted_data = crypto.encrypt_data(json.dumps(cred_data), None)
        
        updated_credential = Credential(
            title=form.title.data,
            encrypted_data=encrypted_data,
            id=credential_id
        )
        
        if data_store.save_credential(username, updated_credential):
            flash('Credential updated successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Failed to update credential.', 'error')
    
    return render_template('add_credential.html', form=form, editing=True)

@app.route('/delete_credential/<credential_id>', methods=['POST'])
def delete_credential(credential_id):
    if 'username' not in session or not session.get('mfa_verified'):
        return redirect(url_for('login'))
    
    username = session['username']
    if data_store.delete_credential(username, credential_id):
        flash('Credential deleted successfully!', 'success')
    else:
        flash('Failed to delete credential.', 'error')
    
    return redirect(url_for('dashboard'))

@app.route('/view_credential/<credential_id>')
def view_credential(credential_id):
    if 'username' not in session or not session.get('mfa_verified'):
        return redirect(url_for('login'))
    
    username = session['username']
    credentials = data_store.get_credentials(username)
    credential = next((c for c in credentials if c.id == credential_id), None)
    
    if not credential:
        return jsonify({'error': 'Credential not found'})
    
    try:
        crypto = CryptoManager()
        decrypted_data = crypto.decrypt_data(credential.encrypted_data)
        cred_data = json.loads(decrypted_data)
        cred_data['title'] = credential.title
        return jsonify(cred_data)
    except Exception:
        return jsonify({'error': 'Failed to decrypt credential'})

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)