from flask_mail import Message
from flask import url_for, render_template, current_app
from itsdangerous import URLSafeTimedSerializer
from . import mail

def send_confirmation_email(user_email):
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    token = serializer.dumps(user_email, salt=current_app.config['SECURITY_PASSWORD_SALT'])
    confirm_url = url_for('main.confirm_email', token=token, _external=True)
    html = render_template('email_confirmation.html', confirm_url=confirm_url)
    subject = "Confirmation d'email"
    msg = Message(recipients=[user_email], subject=subject, html=html)
    mail.send(msg)
    
def generate_confirmation_token(email):
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=current_app.config['SECURITY_PASSWORD_SALT'])

def send_email(to, subject, template):
    msg = Message(
        subject,
        recipients=[to],
        html=template,
        sender=current_app.config['MAIL_DEFAULT_SENDER']
    )
    mail.send(msg)
