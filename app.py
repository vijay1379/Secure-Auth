from flask import Flask, render_template, redirect, url_for, flash, request
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, ValidationError
from flask_mysqldb import MySQL
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import jwt
import datetime
import secrets
import string

app = Flask(__name__)
app.static_folder = 'static'

# MySQL Configuration
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'database'

# Generate a random 32-character secret key
secret_key = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))
app.config['SECRET_KEY'] = secret_key

mysql = MySQL(app)

# Generate a random 16-byte key for AES encryption
key = get_random_bytes(16)

def encrypt_password(password, key):
    cipher = AES.new(key, AES.MODE_ECB)
    padded_password = pad(password.encode('utf-8'), AES.block_size)
    encrypted_password = cipher.encrypt(padded_password)
    return encrypted_password.hex()

def decrypt_password(encrypted_password, key):
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted_password_bytes = bytes.fromhex(encrypted_password)
    decrypted_password = unpad(cipher.decrypt(encrypted_password_bytes), AES.block_size)
    return decrypted_password.decode('utf-8')

def generate_token(user_id):
    payload = {
        'user_id': user_id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)  #Time Change
    }
    token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
    return token

class RegisterForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Register")

    def validate_email(self, field):
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE email=%s", (field.data,))
        user = cursor.fetchone()
        cursor.close()
        if user:
            raise ValidationError('Email Already Taken')

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        password = form.password.data
        encrypted_password = encrypt_password(password, key)
        account_number = ''.join(secrets.choice(string.digits) for _ in range(8))
        cursor = mysql.connection.cursor()
        cursor.execute("INSERT INTO users (name, email, password, account_number, amount) VALUES (%s, %s, %s, %s, %s)", (name, email, encrypted_password, account_number, 1000))
        mysql.connection.commit()
        cursor.close()
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()
        cursor.close()
        if user:
            stored_password = user[3]
            decrypted_password = decrypt_password(stored_password, key)
            if password == decrypted_password:
                user_id = user[0]
                token = generate_token(user_id)
                return redirect(url_for('transactions', token=token))
        flash("Login failed. Please check your email and password")
        return redirect(url_for('login'))
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    flash("You have been logged out successfully.")
    return redirect(url_for('login'))

@app.route('/transactions', methods=['GET','POST'])
def transactions():
    token = request.args.get('token')
    if not token:
        return redirect(url_for('login'))
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = payload['user_id']
    except jwt.ExpiredSignatureError:
        return redirect(url_for('login'))
    except jwt.InvalidTokenError:
        return redirect(url_for('login'))

    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM users WHERE id=%s", (user_id,))
    user = cursor.fetchone()

    if request.method == 'POST':
        transaction_type = request.form.get('transactionType')
        amount = float(request.form.get('amount'))

        if user:
            current_balance = user[5]  # Assuming the balance is stored in the 6th column (index 5)
            if transaction_type == 'deposit':
                new_balance = current_balance + amount
            elif transaction_type == 'withdraw':
                if amount <= current_balance:
                    new_balance = current_balance - amount
                else:
                    flash('Insufficient balance.')
                    return redirect(url_for('transactions', token=token))
            cursor.execute("UPDATE users SET amount=%s WHERE id=%s", (new_balance, user_id))
            mysql.connection.commit()
            flash('Transaction successful.')
            return redirect(url_for('transactions', token=token))

    cursor.close()
    return render_template('transactions.html', user=user, token=token)



if __name__ == "__main__":
   app.run(debug=True)
