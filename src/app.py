import os
import csv
import json
import uuid

from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from flask_mail import Mail
from flask_migrate import Migrate

from wtforms import StringField, PasswordField, TextAreaField, HiddenField
from database import db, User, Credential
from database_manager import DatabaseManager 
from wtforms.validators import DataRequired, Length, Email, EqualTo

from werkzeug.utils import secure_filename

from dotenv import load_dotenv

from cryptography.fernet import Fernet

from .database import db
from .forms import MFAForm

from .database import db
from .database_manager import DatabaseManager
from .models import JSONDataStore, Credential
from .auth import AuthManager
from .crypto import CryptoManager
from .mfa import MFAManager   # or wherever you define it


# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-key-change-in-production')
app.config['WTF_CSRF_ENABLED'] = True

# master pswd used by CryptoManager for en/decryption
MASTER_PASSWORD = os.getenv('ENCRYPTION_KEY', 'dev-master-password')

#db config
basedir = os.path.abspath(os.path.dirname(__file__))
DATA_DIR = os.path.join(basedir, "../data")
os.makedirs(DATA_DIR, exist_ok=True)

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv(
    'DATABASE_URL', f'sqlite:///{os.path.join(DATA_DIR, "vault.db")}'
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# initialize extensions
db.init_app(app)
migrate = Migrate(app, db)

# create table
with app.app_context():
    db.create_all()

# Mail config
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
db_manager = DatabaseManager()
auth_manager = AuthManager()
mfa_manager = MFAManager(mail)

FERNET_KEY = os.getenv('FERNET_KEY')

APP_CRYPTO_KEY = FERNET_KEY
CRYPTO_MANAGER = CryptoManager(FERNET_KEY)

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
    email = StringField('Email', validators=[DataRequired(), Email()])


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
            session['mfa_verified'] = False
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
    if 'username' not in session:
        return redirect(url_for('login'))

    if not session.get('setup_mfa'):
        return redirect(url_for('login'))

    username = session['username']
    user = db_manager.get_user_by_username(username)
    #user = data_store.get_user(username)
    
    if not user:
        return redirect(url_for('login'))
    
    form = MFAForm()

    # Generate QR code
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

    return render_template('setup_mfa.html', qr_code=qr_code, secret=user.mfa_secret,
                           form=form, user=user, is_setup=True)

@app.route('/mfa', methods=['GET', 'POST'])
def mfa_verify():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    user = db_manager.get_user_by_username(username)
    form = MFAForm()

    if form.validate_on_submit():
        otp_code = form.otp_code.data

        # Try TOTP first
        if mfa_manager.verify_totp(user.mfa_secret, otp_code):
            session['mfa_verified'] = True
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        # Try email OTP if user has email
        elif user.email and mfa_manager.verify_email_otp(user.email, otp_code):
            session['mfa_verified'] = True
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid OTP code.', 'error')

    return render_template('setup_mfa.html', form=form, user=user, is_setup=False)


@app.route('/send_email_otp', methods=['POST'])
def send_email_otp():
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Not logged in'})
    
    user = db_manager.get_user_by_username(session['username'])
    if user and user.email:
        if mfa_manager.send_email_otp(user.email):
            return jsonify({'success': True, 'message': 'OTP sent to email'})

    return jsonify({'success': False, 'message': 'Failed to send OTP'})


@app.route('/dashboard')
def dashboard():
    if 'username' not in session or not session.get('mfa_verified'):
        return redirect(url_for('login'))

    username = session['username']
    user = db_manager.get_user_by_username(username)
    #credentials = data_store.get_credentials(username)
    
    if not user:
        return redirect(url_for('login'))
    
    # Get credentials from database
    credentials = Credential.query.filter_by(user_id=user.id).all()
    
    # Convert to list of dicts with decrypted data for display
    credentials_list = []
    crypto = CryptoManager()
    for cred in credentials:
        try:
            decrypted_data = crypto.decrypt_data(cred.encrypted_data)
            cred_dict = json.loads(decrypted_data)
            credentials_list.append({
                'id': str(cred.id),
                'title': cred.title,
                'username': cred_dict.get('username', ''),
                'url': cred_dict.get('url', ''),
                'created_at': cred.created_at,
                'updated_at': cred.updated_at
            })
        except Exception as e:
            print(f"Error decrypting credential {cred.id}: {e}")
            continue
    
    form = CredentialForm()
    #user = data_store.get_user(username)
    
    return render_template('dashboard.html', credentials=credentials_list, form=form, user=user)


@app.route('/add_credential', methods=['POST'])
def add_credential():
    if 'username' not in session or not session.get('mfa_verified'):
        return redirect(url_for('login'))

    form = CredentialForm()
    
    # updating to using database instead of JSON
    # however, process to check if credential is already stored is not here
    if form.validate_on_submit():
        username = session['username']
        user = db_manager.get_user_by_username(username)
        
        if not user:
            flash('User not found.', 'error')
            return redirect(url_for('login'))
        
        # Create credential data
        cred_data = {
            'username': form.username.data,
            'password': form.password.data,
            'url': form.url.data,
            'notes': form.notes.data
        }
        
        # Encrypt credential data
        crypto = CryptoManager()
        encrypted_data = crypto.encrypt_data(json.dumps(cred_data), None)
        
        # Create and save credential
        credential = Credential(
            user_id=user.id,
            title=form.title.data,
            encrypted_data=encrypted_data
        )
        
        db.session.add(credential)
        db.session.commit()
        
        flash('Credential saved successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('add_credential.html', form=form)
    
    
    # uses the JSON data storage method (not DB storage)
    # But checks if credential was already stored
   ''' if not form.validate_on_submit():
        flash('Please fill in the required fields.', 'error')
        return redirect(url_for('dashboard'))

    username = session['username']
    title = form.title.data.strip()

    # Duplicate check
    existing_creds = data_store.get_credentials(username)
    if any(c.title.lower() == title.lower() for c in existing_creds):
        flash('A credential with this title already exists. Please choose a different title.', 'error')
        return redirect(url_for('dashboard'))

    # Build the credential payload
    cred_data = {
        'username': form.username.data,
        'password': form.password.data,
        'url': form.url.data,
        'notes': form.notes.data
    }

    # encrypt credential data using master password from .env
    crypto = CryptoManager(master_password=MASTER_PASSWORD)
    encrypted_data = crypto.encrypt_data(json.dumps(cred_data))

    # make credential object (JSONDataStore version)
    credential = Credential(
        title=title,
        encrypted_data=encrypted_data,
        id=form.credential_id.data if form.credential_id.data else None
    )

    # save and redirect back to dashboard
    if data_store.save_credential(username, credential):
        flash('Credential saved successfully!', 'success')
    else:
        flash('Failed to save credential.', 'error')

    return redirect(url_for('dashboard'))'''



@app.route('/edit_credential/<int:credential_id>', methods=['GET', 'POST'])
def edit_credential(credential_id):
    if 'username' not in session or not session.get('mfa_verified'):
        return redirect(url_for('login'))

    username = session['username']
    user = db_manager.get_user_by_username(username)
    
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('login'))
    
    # Get credential from database with ownership check
    credential = Credential.query.filter_by(id=credential_id, user_id=user.id).first()
    
    #credentials = data_store.get_credentials(username)
    #credential = next((c for c in credentials if c.id == credential_id), None)
    
    if not credential:
        flash('Credential not found.', 'error')
        return redirect(url_for('dashboard'))

    form = CredentialForm()

    if request.method == 'GET':
        # Decrypt and populate form
        try:
            crypto = CryptoManager(master_password=MASTER_PASSWORD)
            decrypted_data = crypto.decrypt_data(credential.encrypted_data)
            cred_data = json.loads(decrypted_data)

            form.title.data = credential.title
            form.username.data = cred_data.get('username', '')
            form.password.data = cred_data.get('password', '')
            form.url.data = cred_data.get('url', '')
            form.notes.data = cred_data.get('notes', '')
            form.credential_id.data = str(credential_id)
        except Exception as e:
            print(f"Error decrypting: {e}")
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
        
        credential.title = form.title.data
        credential.encrypted_data = encrypted_data
        
        db.session.commit()
        
        flash('Credential updated successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('add_credential.html', form=form, editing=True)

@app.route('/delete_credential/<int:credential_id>', methods=['POST'])

# code with JSON storage
    '''    crypto = CryptoManager(master_password=MASTER_PASSWORD)
        encrypted_data = crypto.encrypt_data(json.dumps(cred_data))


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


@app.route('/delete_credential/<credential_id>', methods=['POST'])'''
def delete_credential(credential_id):
    if 'username' not in session or not session.get('mfa_verified'):
        return redirect(url_for('login'))

    username = session['username']
    user = db_manager.get_user_by_username(username)
    
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('login'))
    
    # Delete with ownership check
    credential = Credential.query.filter_by(id=credential_id, user_id=user.id).first()
    if credential:
        db.session.delete(credential)
        db.session.commit()
        flash('Credential deleted successfully!', 'success')
    else:
        flash('Failed to delete credential.', 'error')

    return redirect(url_for('dashboard'))

@app.route('/view_credential/<int:credential_id>')
#@app.route('/view_credential/<credential_id>')

def view_credential(credential_id):
    if 'username' not in session or not session.get('mfa_verified'):
        return redirect(url_for('login'))

    username = session['username']
    user = db_manager.get_user_by_username(username)
    
    if not user:
        return jsonify({'error': 'User not found'})
    
    # Get credential with ownership check
    credential = Credential.query.filter_by(id=credential_id, user_id=user.id).first()
    
    #credentials = data_store.get_credentials(username)
    #credential = next((c for c in credentials if c.id == credential_id), None)

    if not credential:
        return jsonify({'error': 'Credential not found'})

    try:
        crypto = CryptoManager(master_password=MASTER_PASSWORD)
        decrypted_data = crypto.decrypt_data(credential.encrypted_data)

        cred_data = json.loads(decrypted_data)
        cred_data['title'] = credential.title
        return jsonify(cred_data)
    except Exception as e:
        print(f"Error decrypting: {e}")
        return jsonify({'error': 'Failed to decrypt credential'})


@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('login'))

@app.route('/import_google_passwords', methods=['POST'])
def import_google_passwords():
    if 'username' not in session or not session.get('mfa_verified'):
        return redirect(url_for('login'))

    file = request.files.get('file')
    if not file or file.filename == '':
        flash('No file selected. Please choose a CSV file.', 'error')
        return redirect(url_for('dashboard'))

    if not file.filename.endswith('.csv'):
        flash('Invalid file type. Please upload a CSV file.', 'error')
        return redirect(url_for('dashboard'))

    username = session['username']
    crypto = CryptoManager()
    save_path = ""

    try:
        filename = f"{uuid.uuid4()}_{secure_filename(file.filename)}"
        save_path = os.path.join(DATA_DIR, filename)
        file.save(save_path)

        imported_count = failed_count = 0
        with open(save_path, 'r', encoding='utf-8-sig', newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            if reader.fieldnames is None:
                flash('CSV file appears empty.', 'error')
                return redirect(url_for('dashboard'))

            for row in reader:
                try:
                    title = (row.get('name') or row.get('Name') or 'Unnamed Site').strip()
                    url = (row.get('url') or '').strip()
                    uname = (row.get('username') or '').strip()
                    passwd = (row.get('password') or '').strip()
                    notes = (row.get('note') or 'Imported from Google Password Manager').strip()

                    if not any([title, url, uname, passwd]):
                        continue

                    cred_data = {'username': uname, 'password': passwd, 'url': url, 'notes': notes}
                    encrypted_data = crypto.encrypt_data(json.dumps(cred_data), APP_CRYPTO_KEY)

                    if data_store.save_credential(username, Credential(title=title, encrypted_data=encrypted_data)):
                        imported_count += 1
                    else:
                        failed_count += 1
                except Exception as e:
                    failed_count += 1
                    print(f"Error importing row: {e}")

        if imported_count:
            flash(f'Successfully imported {imported_count} credentials. {failed_count} failed.', 'success' if not failed_count else 'warning')
        else:
            flash('No credentials imported. Check CSV format.', 'error')

    except Exception as e:
        flash(f'Error processing CSV: {e}', 'error')
    finally:
        if save_path and os.path.exists(save_path):
            os.unlink(save_path)

    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    app.run(debug=True, port=5000)