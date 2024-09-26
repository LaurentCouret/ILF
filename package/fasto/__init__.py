# __init__.py
from flask import Flask, current_app
from flask_login import LoginManager
from pymongo import MongoClient
from flask_mail import Mail, Message
from bson.objectid import ObjectId
from .models import User
import base64
from apscheduler.schedulers.background import BackgroundScheduler
from datetime import datetime
from itsdangerous import URLSafeTimedSerializer
import urllib.parse

def b64encode(value):
    if value is None:
        return ''
    return base64.b64encode(value).decode('utf-8')

login_manager = LoginManager()
mail = Mail()

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'ioew_hVNfhh46ZkLReHCVw'
   # Mot de passe avec caractères spéciaux
    password = 'iA@A#MAov45Ug^'
    # Encoder le mot de passe pour l'URL
    encoded_password = urllib.parse.quote_plus(password)
    # MongoDB configuration
    client = MongoClient('mongodb://localhost:27017/')
    app.db = client['ILF']

 # Flask-Mail configuration
    app.config['MAIL_SERVER'] = 'smtp.ionos.fr'
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USE_SSL'] = False
    app.config['MAIL_USERNAME'] = 'contact@institutdelabelisationfrancais.fr'
    app.config['MAIL_PASSWORD'] = 'Cestparicilamoulatpourlfp2024'
    app.config['MAIL_DEFAULT_SENDER'] = 'contact@institutdelabelisationfrancais.fr'
    app.config['SECURITY_PASSWORD_SALT'] = 'dfdsfdsfrgfdhjnhgghjfgfh'
    app.config['ADMIN_EMAIL'] = 'contact@institutdelabelisationfrancais.fr'  # Adresse email de l'administrateur
    mail.init_app(app)

# Flask-Login configuration

    login_manager.login_view = 'main.page_login'
    login_manager.init_app(app)

    from .routes import main as main_blueprint
    app.register_blueprint(main_blueprint)

    @login_manager.user_loader
    def load_user(user_id):
        user_data = app.db.users.find_one({"_id": ObjectId(user_id)})
        if user_data:
            return User.from_db(user_data)
        return None
    
    # Adding b64encode filter
    app.jinja_env.filters['b64encode'] = b64encode
    
    start_scheduler(app)

    return app

def check_labels():
    with current_app.app_context():
        users = current_app.db.users.find({"role": "formateur"})
        for user_data in users:
            user = User.from_db(user_data)
            if user.label_obtained_date and not user.email_sent:
                days_remaining = 365 - (datetime.now() - user.label_obtained_date).days
                if days_remaining <= 0:
                    # Envoyer un email au formateur
                    send_renewal_email(user)
                    user.email_sent = True
                    user.save()

def send_renewal_email(user):
    subject = "Renouvellement de votre label"
    sender = current_app.config['MAIL_DEFAULT_SENDER']
    recipients = [user.email]
    body = f"Bonjour {user.prenom},\n\nVotre label doit être renouvelé. Veuillez prendre rendez-vous pour le renouvellement.\n\nCordialement,\nL'équipe de l'Institut de labélisation français"
    
    send_email(subject, sender, recipients, body)

def send_email(subject, sender, recipients, body):
    msg = Message(subject, sender=sender, recipients=recipients)
    msg.body = body
    mail.send(msg)

def start_scheduler(app):
    scheduler = BackgroundScheduler()
    
    def job_function():
        with app.app_context():
            check_labels()
    
    scheduler.add_job(job_function, 'interval', days=1)  # Intervalle d'un jour
    scheduler.start()

def generate_reset_token(email):
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=current_app.config['SECURITY_PASSWORD_SALT'])

def confirm_reset_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    try:
        email = serializer.loads(token, salt=current_app.config['SECURITY_PASSWORD_SALT'], max_age=expiration)
    except:
        return False
    return email

def send_reset_email(to_email, reset_url):
    subject = "Réinitialisation de votre mot de passe"
    body = f"""
    <html>
    <body>
        <p>Bonjour,</p>
        <p>Veuillez cliquer sur le lien suivant pour réinitialiser votre mot de passe :</p>
        <p><a href="{reset_url}">Réinitialiser mon mot de passe</a></p>
        <p>Si vous n'avez pas demandé de réinitialisation de mot de passe, veuillez ignorer cet email.</p>
        <br>
        <p>Cordialement,</p>
        <p>L'équipe de l'Institut Labélisation Français</p>
    </body>
    </html>
    """
    
    msg = Message(subject, sender=current_app.config['MAIL_DEFAULT_SENDER'], recipients=[to_email])
    msg.html = body  # Utiliser msg.html pour envoyer un email au format HTML
    mail.send(msg)

