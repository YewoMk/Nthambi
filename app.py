
from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, Email, EqualTo, Regexp, ValidationError
from flask_bootstrap import Bootstrap5
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from itsdangerous import URLSafeTimedSerializer as Serializer
from flask_mail import Mail, Message
import random
# import email_validator
import requests



app = Flask(__name__)
app.config['SECRET_KEY'] = 'cryptography'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# Email configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  #  email server
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'yewomkandawire1@gmail.com'  # email
app.config['MAIL_PASSWORD'] = 'nhwd obhz gcjc hjyw'  # email password
app.config['MAIL_DEFAULT_SENDER'] = ('Nthambi', 'yewomkandawire1@gmail.com'	)
app.config['MAIL_MAX_EMAILS'] = None
app.config['MAIL_DEBUG'] = True


db = SQLAlchemy(app)
bootstrap = Bootstrap5(app)
bcrypt = Bcrypt(app)
mail = Mail(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

#Database models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    confirmed = db.Column(db.Boolean, nullable=False, default=False)

    def generate_confirmation_token(self, expiration=1300):
        s = Serializer(app.config['SECRET_KEY'])
        return s.dumps({'confirm': str(self.id)})  # Convert id to string
    
    def confirm(self, token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
            if int(data.get('confirm')) != self.id:  # Convert back to int for comparison
                return False
            self.confirmed = True
            db.session.add(self)
            return True
        except:
            return False

    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"

#Forms
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    # Email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    submit = SubmitField('login')

class resetform(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Reset Password')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(1, 64),
                                Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
                                'Usernames must have only letters, numbers, dots or '
                                'underscores')])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    password2 = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password', message='Passwords must match')])
    submit = SubmitField('Sign-Up')

    def validate_username(self, username):
        existing_user = User.query.filter_by(username=username.data).first()
        if existing_user:
            raise ValidationError('Username already exists. Please choose a different one.')

def send_confirmation_email(user, token):
    try:
        subject = "Please Confirm Your Account"
        msg = Message(
            subject,
            recipients=[user.email]
        )
        
        # Set both HTML and text bodies
        msg.body = render_template('confirm.txt', user=user, token=token)
        msg.html = render_template('confirm.html', user=user, token=token)
        
        print(f"Attempting to send email to {user.email}")
        print(f"Token generated: {token}")
        
        mail.send(msg)
        print(f"Confirmation email sent successfully to {user.email}")
        return True
    except Exception as e:
        print(f"Failed to send confirmation email: {str(e)}")
        print(f"User: {user.username}, Email: {user.email}")
        import traceback
        print(f"Full traceback: {traceback.format_exc()}")
        return False

@app.route('/', methods=['GET', 'POST'])
@app.route('/home')
def home():
    return render_template("home.html")


@app.route('/reset', methods=['GET', 'POST'])
def reset():
    form = resetform()
    return render_template("reset.html", form=form)

@app.route('/test-email')
def test_email():
    try:
        msg = Message('Test Email',
                    recipients=[app.config['MAIL_USERNAME']])
        msg.body = "This is a test email"
        mail.send(msg)
        return 'Test email sent! Check your inbox.'
    except Exception as e:
        return f'Error sending email: {str(e)}'

@app.route('/confirm/<token>')
@login_required
def confirm(token):
    if current_user.confirmed:
        return redirect(url_for('login'))
    if current_user.confirm(token):
        db.session.commit()
        flash('You have confirmed your account. Thanks!', 'success')
    else:
        flash('The confirmation link is invalid or has expired.', 'danger')
    return redirect(url_for('login'))

@app.route('/confirm')
@login_required
def resend_confirmation():
    token = current_user.generate_confirmation_token()
    if send_confirmation_email(current_user, token): 
        flash('A new confirmation email has been sent to you.', 'success')
    else:
        flash('There was a problem sending the confirmation email.', 'danger')
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            return render_template("login.html", form=form, error="Invalid username or password")
    return render_template("login.html", form=form)

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    form = LoginForm()
    # current_user = User.query.filter_by(username=form.username.data).first()
    return render_template("dashboard.html" , username=current_user.username)


@app.route('/Register', methods=['GET', 'POST'])
def Register():
    form = RegistrationForm()
    if form.validate_on_submit():
        try:
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            user = User(
                username=form.username.data,
                email=form.email.data, 
                password=hashed_password,
                confirmed=False
            )


            token = user.generate_confirmation_token()

            if send_confirmation_email(user, token):
                flash('Registration successful! Please check your email to confirm your account.', 'success')
            else:
                flash('Registration successful but there was a problem sending the confirmation email. Please contact support.', 'warning')
                

            db.session.add(user)
            db.session.commit()

            # return redirect(url_for('login'))
        
        except Exception as e:
            db.session.rollback()
            print(f"Registration error: {str(e)}")
            flash('An error occurred during registration. Please try again.', 'danger')


    return render_template("Register.html", form=form )


@app.route('/checkout', methods=['GET', 'POST'])
def checkout():
    if request.method == 'POST':
        try:
            # Capture form data
            first_name = request.form.get('first_name')
            last_name = request.form.get('last_name')
            email = request.form.get('email')
            amount = request.form.get('amount')

            # Generate transaction reference
            tx_ref = str(random.randint(1000000000, 9999999999))

            # PayChangu API configuration
            url = "https://api.paychangu.com/payment"
            NGROK_URL = "https://3f56-102-70-10-240.ngrok-free.app"  # Your actual ngrok URL

            payload = {
                "amount": str(amount),
                "currency": "MWK",
                "email": email,
                "first_name": first_name,
                "last_name": last_name,
                "callback_url": f"{NGROK_URL}/payment/callback",
                "return_url": f"{NGROK_URL}/payment/return",
                "tx_ref": tx_ref,
                "customization": {
                    "title": "Donation Payment",
                    "description": "Charity donation"
                }
            }

            headers = {
                "accept": "application/json",
                "Authorization": "Bearer SEC-TEST-kRpuJzHIFbZyxrU0CrzUtmFKFHB4Ax3G",  # Your secret key
                "content-type": "application/json"
            }

            # Make API request
            response = requests.post(url, json=payload, headers=headers)

            # Log the full response for debugging
            print("PayChangu Response Status Code:", response.status_code)
            print("PayChangu Response Text:", response.text)
            
            if response.status_code in [200, 201]:
                response_data = response.json()
                print("PayChangu Response JSON:", response_data)

                if response_data.get('status') == 'success':
                    checkout_url = response_data.get('data', {}).get('checkout_url')
                    if checkout_url:
                        print("Redirecting to:", checkout_url)
                        return redirect(checkout_url)
                    else:
                        flash("No checkout URL provided in the response", "error")
                else:
                    flash(f"Payment error: {response_data.get('message', 'Unexpected error occurred.')}", "error")
            else:
                flash(f"Error: {response.status_code} - {response.text}", "error")

        except Exception as e:
            flash(f"An error occurred: {str(e)}", "error")
            print(f"Exception details: {str(e)}")  # Add detailed logging

        return redirect(url_for('checkout'))

    return render_template("checkout.html")

@app.route('/payment/callback', methods=['POST'])
def payment_callback():
    data = request.json
    print("Payment callback received:", data)  # For debugging
    return '', 200

@app.route('/payment/return')
def payment_return():
    tx_ref = request.args.get('tx_ref')
    status = request.args.get('status')
    
    if status == 'failed':
        flash("Payment failed. Please try again.", "error")
        return redirect(url_for('checkout'))
    
    flash(f"Payment completed with status: {status}", "success")
    return redirect(url_for('home'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # db.drop_all() 
    # with app.app_context():
    #     try:
    #         msg = Message(
    #             "Test Email",
    #             recipients=[app.config['MAIL_USERNAME']]
    #         )
    #         msg.body = "This is a test email to verify the email configuration."
    #         mail.send(msg)
    #         print("Email configuration test successful!")
    #     except Exception as e:
    #         print(f"Email configuration test failed: {str(e)}") 
    app.run(debug=True)
    