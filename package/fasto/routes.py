#routes.py
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, current_app
from flask_login import login_user, login_required, logout_user, current_user
from .models import User, ContactMessage
from .email import send_confirmation_email, send_discord_invitation_email
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Message
import logging
import base64
import random
import string
from . import mail
from bson.objectid import ObjectId
import stripe
from datetime import datetime, timedelta
from fpdf import FPDF
from .models import User, ContactMessage
from . import generate_reset_token, send_reset_email, confirm_reset_token
import unicodedata
from werkzeug.utils import secure_filename
import io
import os
import json
from PIL import Image
from time import time
import pytz
from .models import Visit
import re
import random
import string
import requests


def resize_and_encode_image(image_file, max_size=(300, 300)):
    img = Image.open(image_file)
    img.thumbnail(max_size)
    
    buffer = io.BytesIO()
    
    # Vérification du mode de l'image pour voir s'il y a de la transparence (mode RGBA)
    if img.mode == 'RGBA':
        # Convertir en PNG pour préserver la transparence
        img.save(buffer, format="PNG")
    else:
        # Convertir en JPEG si aucune transparence
        img.convert('RGB').save(buffer, format="JPEG")
    
    buffer.seek(0)
    img_base64 = base64.b64encode(buffer.read()).decode('utf-8')
    
    return img_base64



# Configuration de l'API Stripe pour les paiements
stripe.api_key = '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'
stripe_public_key = 'pk_live_51PxX8GKsrT3yjgVUb0DhF84Khrq4xkYfJHH0TC8amOVuHzFdUohWxJwlnf2lTPGJFSEEYuDpypCE5VxvXzk8PW1y00KEoI5cyF'

# Initialisation de la configuration du logger
logging.basicConfig(level=logging.DEBUG)

# Création du blueprint pour gérer les routes de l'application
main = Blueprint('main', __name__)

# Route pour la page d'accueil
@main.route("/")
def home():
    # Enregistrement de la visite
    visit = Visit(
        url=request.path,
        user_agent=request.headers.get('User-Agent'),
        visit_time=datetime.now()
    )
    visit.save()
    
    return render_template("fasto/accueil/index.html")

@main.route('/end_visit', methods=['POST'])
def end_visit():
    data = request.get_json()
    duration = data.get('duration')
    
    print(f"Requête reçue avec les données : {data}")  # Debugging

    # Mettre à jour la dernière visite de l'utilisateur avec la durée
    result = current_app.db.visits.update_one(
        {'user_agent': request.headers.get('User-Agent')},  # Filtre par user_agent
        {'$set': {'duration': duration}},
        upsert=False
    )
    
    if result.modified_count == 0:
        print("Aucune entrée mise à jour")
    
    return jsonify(success=True)




@main.route("/notrehistoire")
def notrehistoire():
    return render_template("fasto/accueil/notrehistoire.html")

@main.route("/partenariat")
def partenariat():
    return render_template("fasto/accueil/partenariat.html")

@main.route("/nousrejoindre")
def nousrejoindre():
    return render_template("fasto/accueil/nousrejoindre.html")

@main.route("/discord")
def discord():
    return render_template("fasto/accueil/discord.html")

# Route pour la page de choix d'inscription
@main.route("/page-register-choice")
def page_register_choice():
    return render_template("fasto/pages/page-register-choice.html")

# Route pour la page de choix d'inscription
@main.route("/register-formateur", methods=["GET", "POST"])
def register_formateur():
    if request.method == "POST":
        
        # Récupérer le code d'affiliation s'il est fourni
        affiliation_code = request.form.get("affiliation_code")
        
        # Vérifier l'existence du code d'affiliation dans la base de données
        ambassador = None
        if affiliation_code:
            ambassador = User.get_by_affiliation_code(affiliation_code)
            logging.debug(f"Code d'affiliation saisi : {affiliation_code}")
            logging.debug(f"Ambassadeur trouvé : {ambassador}")

            if not ambassador or ambassador.role != "ambassadeur":
                flash("Code d'affiliation invalide.", "danger")
                return redirect(url_for("main.register_formateur"))

            
       # Récupération de la réponse reCAPTCHA
        recaptcha_response = request.form.get("g-recaptcha-response")
        if not recaptcha_response:
            flash("Veuillez compléter le reCAPTCHA.", "danger")
            return redirect(url_for("main.register_formateur"))

        # Vérification reCAPTCHA avec la clé secrète
        recaptcha_secret = "6LfEyXsqAAAAAD5sR4Jp-Rw8XDMuIBzLFuENfO7k"
        recaptcha_verification_url = "https://www.google.com/recaptcha/api/siteverify"
        recaptcha_payload = {
            "secret": recaptcha_secret,
            "response": recaptcha_response
        }
        recaptcha_response = requests.post(recaptcha_verification_url, data=recaptcha_payload).json()

        # Vérifier si reCAPTCHA est réussi
        if not recaptcha_response.get("success"):
            flash("Échec de la vérification reCAPTCHA. Veuillez réessayer.", "danger")
            return redirect(url_for("main.register_formateur"))
        
        # Si le reCAPTCHA est validé, on continue avec l'enregistrement
        # Récupération des données du formulaire
        nom = request.form.get("nom")
        prenom = request.form.get("prenom")
        secteur = request.form.get("secteur")
        competences_json = request.form.get("competences")
        email = request.form.get("email")
        confirm_email = request.form.get("confirm_email")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")
        photo_profil = None


        # Validation du nom et prénom avec une regex
        if not re.match(r"^[A-Za-zÀ-ÿ' -]+$", nom):
            flash("Le nom ne peut contenir que des lettres, des espaces, des traits d'union ou des apostrophes.", "danger")
            return redirect(url_for("main.register_formateur"))

        if not re.match(r"^[A-Za-zÀ-ÿ' -]+$", prenom):
            flash("Le prénom ne peut contenir que des lettres, des espaces, des traits d'union ou des apostrophes.", "danger")
            return redirect(url_for("main.register_formateur"))

        # Vérification de la correspondance des emails
        if email != confirm_email:
            flash("Les emails ne correspondent pas.", "danger")
            return redirect(url_for("main.register_formateur"))

        # Vérification de la correspondance des mots de passe
        if password != confirm_password:
            flash("Les mots de passe ne correspondent pas.", "danger")
            return redirect(url_for("main.register_formateur"))

        # Vérification de la force du mot de passe
        password_regex = r"^(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*(),.?\":{}|<>;'\[\]\-_/+=~`])[A-Za-z\d!@#$%^&*(),.?\":{}|<>;'\[\]\-_/+=~`]{15,}$"
        if not re.match(password_regex, password):
            flash("Le mot de passe doit contenir au moins 15 caractères, une majuscule, un chiffre et un caractère spécial.", "danger")
            return redirect(url_for("main.register_formateur"))



        # Vérification si l'utilisateur existe déjà
        user = User.get_by_email(email)
        if user:
            flash("Cet email est déjà utilisé.", "danger")
            return redirect(url_for("main.register_formateur"))

        # Gestion des compétences (parser JSON ou fallback)
        try:
            competences = json.loads(competences_json)  # Traiter comme un tableau d'objets JSON
            competences = [{"value": comp["value"]} for comp in competences]  # Extraire les valeurs
        except ValueError:
            competences = [{"value": comp.strip()} for comp in competences_json.split(',')]  # Fallback si JSON invalide

        # Gestion de l'image de profil
        if 'photo_profil' in request.files:
            photo_profil_file = request.files['photo_profil']
            if photo_profil_file:
                photo_profil_file.seek(0)  # Remettre le pointeur au début après lecture
                photo_profil = resize_and_encode_image(photo_profil_file)
                print("Photo de profil traitée.")

        # Création d'un nouvel utilisateur
        new_user = User(
            nom=nom,
            prenom=prenom,
            secteur=secteur,
            competences=competences,
            email=email,
            password=password,
            role="formateur",
            photo_profil=photo_profil,
            label_obtained_date=datetime.now()
        )

        # Sauvegarde de l'utilisateur
        new_user.save()

        # Associer le formateur à l'ambassadeur
        if ambassador:
            ambassador.add_affiliated_user(new_user.email)
            
        # Envoi de l'email de confirmation
        send_confirmation_email(email)    
        flash("Compte formateur créé avec succès. Veuillez vérifier votre email pour activer votre compte.", "success")
        return redirect(url_for("main.page_login"))

    return render_template("fasto/pages/page-register-formateur.html")



# Route pour l'inscription des écoles
@main.route("/register-ecole", methods=["GET", "POST"])
def register_ecole():
    if request.method == "POST":
        # Récupération de la réponse reCAPTCHA
        recaptcha_response = request.form.get("g-recaptcha-response")
        if not recaptcha_response:
            flash("Veuillez compléter le reCAPTCHA.", "danger")
            return redirect(url_for("main.register_formateur"))

        # Vérification reCAPTCHA avec la clé secrète
        recaptcha_secret = "6LfEyXsqAAAAAD5sR4Jp-Rw8XDMuIBzLFuENfO7k"
        recaptcha_verification_url = "https://www.google.com/recaptcha/api/siteverify"
        recaptcha_payload = {
            "secret": recaptcha_secret,
            "response": recaptcha_response
        }
        recaptcha_response = requests.post(recaptcha_verification_url, data=recaptcha_payload).json()

        # Vérifier si reCAPTCHA est réussi
        if not recaptcha_response.get("success"):
            flash("Échec de la vérification reCAPTCHA. Veuillez réessayer.", "danger")
            return redirect(url_for("main.register_formateur"))
        # Récupération des données du formulaire
        nom = request.form.get("nom")
        prenom = request.form.get("prenom")
        status = request.form.get("status")
        email = request.form.get("email")
        confirm_email = request.form.get("confirm_email")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")
        telephone = request.form.get("telephone")
        ecole = request.form.get("ecole")

        # Validation du nom et prénom avec une regex
        if not re.match(r"^[A-Za-zÀ-ÿ' -]+$", nom):
            flash("Le nom ne peut contenir que des lettres, des espaces, des traits d'union ou des apostrophes.", "danger")
            return redirect(url_for("main.register_ecole"))

        if not re.match(r"^[A-Za-zÀ-ÿ' -]+$", prenom):
            flash("Le prénom ne peut contenir que des lettres, des espaces, des traits d'union ou des apostrophes.", "danger")
            return redirect(url_for("main.register_ecole"))

        # Vérification de la correspondance des emails
        if email != confirm_email:
            flash("Les emails ne correspondent pas.", "danger")
            return redirect(url_for("main.register_ecole"))

        # Vérification de la correspondance des mots de passe
        if password != confirm_password:
            flash("Les mots de passe ne correspondent pas.", "danger")
            return redirect(url_for("main.register_ecole"))

        # Vérification si l'utilisateur existe déjà
        user = User.get_by_email(email)
        if user:
            flash("Cet email est déjà utilisé.", "danger")
            return redirect(url_for("main.register_ecole"))

        # Création d'un nouvel utilisateur (école)
        new_user = User(
            nom=nom,
            prenom=prenom,
            status=status,
            email=email,
            password=password,
            telephone=telephone,
            ecole=ecole,
            role="ecole",
            label_obtained_date=datetime.now()
        )
        new_user.save()

        # Envoi de l'email de confirmation
        send_confirmation_email(email)
        flash("Compte école créé avec succès. Veuillez vérifier votre email pour activer votre compte.", "success")
        return redirect(url_for("main.page_login"))

    return render_template("fasto/pages/page-register-ecole.html")

# Route pour la connexion des utilisateurs
@main.route("/page-login", methods=["GET", "POST"])
def page_login():
    if request.method == "POST":
        # Récupération des données du formulaire de connexion
        email = request.form.get("email")
        password = request.form.get("password")
        logging.debug(f"Tentative de connexion pour l'email: {email}")
        user = User.get_by_email(email)

        # Vérification si l'utilisateur existe
        if user:
            logging.debug(f"Utilisateur trouvé: {user.email}, email confirmé: {user.email_confirmed}")
            # Vérification du mot de passe
            if user.check_password(password):
                logging.debug("Le mot de passe correspond.")
                # Vérification si l'email est confirmé
                if not user.email_confirmed:
                    flash("Veuillez confirmer votre adresse e-mail avant de vous connecter.", "warning")
                    return redirect(url_for("main.page_login"))
                login_user(user)
                return redirect(url_for("main.index"))
            else:
                logging.debug("Le mot de passe ne correspond pas.")
        else:
            logging.debug("Utilisateur non trouvé.")
        flash("Email ou mot de passe incorrect.", "danger")
    return render_template("fasto/pages/page-login.html")

# Route pour la déconnexion des utilisateurs
@main.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("main.page_login"))

# Route pour le tableau de bord (dashboard) après connexion
@main.route("/index")
@login_required
def index():

    # Récupération des totaux depuis la base de données
    total_formateurs = current_app.db.users.count_documents({"role": "formateur"})
    total_ecoles = current_app.db.users.count_documents({"role": "ecole"})

    # Calcul des pourcentages de satisfaction des questionnaires
    feedback_counts = current_app.db.questionnaires.aggregate([
        {"$unwind": "$responses"},
        {"$group": {
            "_id": "$responses.satisfaction_prestation",
            "count": {"$sum": 1}
        }}
    ])
    feedback_totals = {doc['_id']: doc['count'] for doc in feedback_counts}
    total_responses = sum(feedback_totals.values())
    feedback_percentages = {
        "Très satisfait": feedback_totals.get("Très satisfait", 0) / total_responses * 100 if total_responses > 0 else 0,
        "Satisfait": feedback_totals.get("Satisfait", 0) / total_responses * 100 if total_responses > 0 else 0,
        "Peu satisfait": feedback_totals.get("Peu satisfait", 0) / total_responses * 100 if total_responses > 0 else 0,
        "Pas satisfait": feedback_totals.get("Pas satisfait", 0) / total_responses * 100 if total_responses > 0 else 0
    }

    context = {
        "user": current_user,
        "page_title": "Dashboard",
        "total_formateurs": total_formateurs,
        "total_ecoles": total_ecoles,
        "feedback_percentages": feedback_percentages
    }

    # Redirection vers le bon tableau de bord selon le rôle de l'utilisateur
    if current_user.role == "admin":
        # Pour l'admin : charger les données des formateurs et des écoles
        formateurs = list(current_app.db.users.find({
            "$or": [
                {"role": "formateur"},
                {"role": {"$regex": "ambassadeur"}}
            ]
        }))
        ecoles = list(current_app.db.users.find({"role": "ecole"}))
        
        # Récupérer les statistiques de visites
        total_visits = current_app.db.visits.count_documents({})
        visit_stats = list(current_app.db.visits.aggregate([
            {"$group": {"_id": "$url", "count": {"$sum": 1}, "avg_duration": {"$avg": "$duration"}}}
        ]))

        context.update({
            "formateurs": formateurs,
            "total_formateurs": len(formateurs),
            "total_ecoles": len(ecoles),
            "total_visits": total_visits,
            "visit_stats": visit_stats
        })

        return render_template("fasto/admin_dashboard.html", **context)

    elif "formateur" in current_user.role or "ambassadeur" in current_user.role:
    # Pour les formateurs et ambassadeurs : calculer les jours restants pour le label
        days_remaining = 365 - (datetime.now() - current_user.label_obtained_date).days
        days_remaining = max(days_remaining, 0)
        context.update({
            "days_remaining": days_remaining,
            "can_schedule": not current_app.db.meetings.find_one({"user_id": current_user.id, "status": "confirmed"}),
             "unique_code": current_user.unique_code  
        })
        return render_template("fasto/formateur_dashboard.html", **context)

    elif current_user.role == "ecole":
        # Pour les écoles : afficher les formateurs
        formateurs = list(current_app.db.users.find({"role": {"$regex": "formateur"}}))
        context.update({
            "formateurs": formateurs
        })
        return render_template("fasto/ecole_dashboard.html", **context)

    return "Unauthorized", 403

@main.route('/admin_dashboard', methods=['GET'])
@login_required
def admin_dashboard():
    if current_user.role != "admin":
        flash("Vous n'êtes pas autorisé à accéder à cette page.", "danger")
        return redirect(url_for('main.index'))

    try:
        # Récupérer les formateurs et ambassadeurs
        formateurs = list(
            current_app.db.users.find(
                {"role": {"$regex": "formateur"}},
                {"password_hash": 0}
            )
        )

        # Collecte des statistiques
        total_formateurs = len(formateurs)
        total_ecoles = current_app.db.users.count_documents({"role": "ecole"})
        total_visits = current_app.db.visits.count_documents({})

        visit_stats = list(current_app.db.visits.aggregate([
            {"$group": {"_id": "$url", "count": {"$sum": 1}, "avg_duration": {"$avg": "$duration"}}}
        ]))

        context = {
            "formateurs": formateurs,
            "total_formateurs": total_formateurs,
            "total_ecoles": total_ecoles,
            "total_visits": total_visits,
            "visit_stats": visit_stats
        }
    except Exception as e:
        flash(f"Erreur lors du chargement des données : {e}", "danger")
        context = {
            "formateurs": [],
            "total_formateurs": 0,
            "total_ecoles": 0,
            "total_visits": 0,
            "visit_stats": []
        }

    return render_template('fasto/admin_dashboard.html', **context)


# Route pour mettre à jour le statut d'un formateur (admin seulement)
@main.route('/update_formateur_status', methods=['POST'])
@login_required
def update_formateur_status():
    if current_user.role != 'admin':
        flash("Vous n'êtes pas autorisé à effectuer cette action.", "danger")
        return redirect(url_for('main.index'))

    formateur_id = request.form.get('formateur_id')
    new_status = request.form.get('new_status')
    
    if not formateur_id or not new_status:
        flash("Erreur : ID du formateur ou nouveau statut manquant.", "danger")
        return redirect(url_for('main.admin_dashboard'))
    
    result = current_app.db.users.update_one(
        {"_id": ObjectId(formateur_id), "role": {"$regex": "formateur"}},
        {"$set": {"status": new_status}}
    )

    if result.modified_count == 1:
        # Optionnel : envoyer un email de notification au formateur
        formateur = current_app.db.users.find_one({"_id": ObjectId(formateur_id)})
        if formateur:
            send_status_email(formateur, new_status)
        
        flash("Le statut du formateur a été mis à jour avec succès.", "success")
        return redirect(url_for('main.admin_dashboard'))
    else:
        flash("Erreur lors de la mise à jour du statut.", "danger")
        return redirect(url_for('main.admin_dashboard'))

# Fonction pour envoyer un email en fonction du nouveau statut d'un formateur
def send_status_email(formateur, new_status):
    """Envoie un email au formateur en fonction du nouveau statut."""
    if new_status == 'Valider':
        subject = "Félicitations, vous avez été labélisé!"
        body = f"Bonjour {formateur['prenom']} {formateur['nom']},\n\nFélicitations! Votre demande de label a été acceptée. Vous êtes maintenant officiellement labélisé."
    elif new_status == 'Suspendu':
        subject = "Attention: Votre label a été suspendu"
        body = f"Bonjour {formateur['prenom']} {formateur['nom']},\n\nVotre label a été temporairement suspendu. Veuillez contacter notre équipe pour plus d'informations."
    elif new_status == 'Rejeter':
        subject = "Votre demande de label a été rejetée"
        body = f"Bonjour {formateur['prenom']} {formateur['nom']},\n\nNous regrettons de vous informer que votre demande de label a été rejetée. Pour en savoir plus, veuillez contacter l'équipe administrative."

    msg = Message(subject, sender=current_app.config['MAIL_DEFAULT_SENDER'], recipients=[formateur['email']])
    msg.body = body
    mail.send(msg)
    

# Route pour confirmer l'email d'un utilisateur via un token
@main.route("/confirm/<token>")
def confirm_email(token):
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    try:
        email = serializer.loads(token, salt=current_app.config['SECURITY_PASSWORD_SALT'], max_age=3600)
    except:
        flash("Le lien de confirmation est invalide ou a expiré.", "danger")
        return redirect(url_for("main.page_login"))
    
    user = User.get_by_email(email)
    if user.email_confirmed:
        flash("Compte déjà confirmé. Veuillez vous connecter.", "success")
    else:
        user.email_confirmed = True
        current_app.db.users.update_one({"email": email}, {"$set": {"email_confirmed": True}})
        flash("Votre compte a été confirmé avec succès!", "success")
        
        # Envoi de l'email d'invitation Discord
        send_discord_invitation_email(email)

    return redirect(url_for("main.page_login"))


@main.route('/calendar')
@login_required
def calendar():
    return render_template('fasto/calendar.html', stripe_public_key=stripe_public_key)

paris_tz = pytz.timezone('Europe/Paris')

@main.route('/calendar_data')
@login_required
def calendar_data():
    offset = int(request.args.get('offset', 0))
    start_date = datetime.now(paris_tz) + timedelta(days=offset * 7)
    
    dates = []
    for i in range(7):
        day_date = start_date + timedelta(days=i)
        day_slots = generate_slots(day_date)
        dates.append({
            'day': day_date.strftime('%A'),  # Jour de la semaine en français
            'date': day_date.strftime('%d %B'),  # Jour et mois en français
            'slots': day_slots
        })
    
    return jsonify({'dates': dates})

def generate_slots(day_date):
    slots = []
    times = [(8, 0), (10, 0), (13, 0), (15, 0), (17, 0)]
    if day_date.weekday() == 5:  # Samedi
        times = [(8, 30), (10, 30), (12, 30)]
    elif day_date.weekday() in [1, 3]:  # Mardi ou Jeudi matin indisponible
        times = [(13, 0), (15, 0), (17, 0)]
    
    for time in times:
        slot_time = day_date.replace(hour=time[0], minute=time[1])
        slots.append({
            'time': slot_time.strftime('%H:%M'),
            'booked': is_slot_booked(slot_time)
        })
    
    return slots

def is_slot_booked(slot_time):
    slot_date_str = slot_time.strftime('%Y-%m-%d')  # Ensure date format matches how it's stored in MongoDB
    slot_time_str = slot_time.strftime('%H:%M')  # Ensure time format matches


    meeting = current_app.db.meetings.find_one({
        'date': slot_date_str,
        'time': slot_time_str,
        'status': 'confirmed'
    })

    if meeting:
        print("Réunion trouvée, créneau réservé.")
        return True
    else:
        print("Aucune réunion trouvée, créneau disponible.")
        return False


@main.route('/calendar', methods=['POST'])
@login_required
def book_slot():
    data = request.get_json()
    slot = data.get('slot')

    if slot:
        date, time = slot.split(' à ')
        current_app.db.meetings.insert_one({
            'user_id': current_user.id,
            'date': date,
            'time': time,
            'status': 'confirmed'
        })
        return jsonify(success=True)
    return jsonify(success=False), 400



# Dictionnaire des mois en français (normalisés)
mois_annee = {
    "janvier": "Janvier",
    "février": "Février",
    "mars": "Mars",
    "avril": "Avril",
    "mai": "Mai",
    "juin": "Juin",
    "juillet": "Juillet",
    "août": "Août",
    "septembre": "Septembre",
    "octobre": "Octobre",
    "novembre": "Novembre",
    "décembre": "Décembre"
}

def normalize_string(input_str):
    """Normalise une chaîne de caractères en retirant les accents."""
    return unicodedata.normalize('NFKD', input_str).encode('ASCII', 'ignore').decode('utf-8')

@main.route('/check_slot_availability', methods=['GET'])
def check_slot_availability():
    date_str = request.args.get('date')  # Format 'YYYY-MM-DD'
    time_str = request.args.get('time')  # Format 'HH:MM'

    # Convertir la date au format utilisé dans la BDD
    date_obj = datetime.strptime(date_str, '%Y-%m-%d')
    jour_fr = date_obj.strftime('%A')

    # Extraire le mois, appliquer le bon encodage puis normaliser
    mois_fr_key = date_obj.strftime('%B').encode('latin1').decode('utf-8')
    print(f"Month extracted: {mois_fr_key}")  # Debugging

    mois_fr = mois_annee.get(mois_fr_key.lower())  # Recherche du mois dans le dictionnaire

    if mois_fr is None:
        print(f"Erreur : Mois non trouvé pour {mois_fr_key}")
        return jsonify({'error': 'Month not found'}), 500

    # Construire la chaîne de date formatée (sans zéro devant le jour)
    formatted_date = f"{jour_fr.capitalize()} {date_obj.day} {mois_fr.lower()}"
    print(f"Formatted date: {formatted_date}, Time: {time_str}")  # Debugging
    print(f"Querying MongoDB with: date={formatted_date}, time={time_str}")

    # Requête pour vérifier si ce créneau est réservé
    meeting = current_app.db.meetings.find_one({
        'date': {"$regex": f"^{formatted_date}$", "$options": "i"},  
        'time': time_str,
        'status': 'confirmed'
    })

    if meeting:
        return jsonify({'booked': True})
    else:
        return jsonify({'booked': False})



@main.route('/block_date', methods=['POST'])
@login_required
def block_date():
    data = request.get_json()
    date = data.get('date')
    time = data.get('time')

    if not date or not time:
        return jsonify({'error': 'Date ou heure manquante.'}), 400

    # Vérification si la date et l'heure sont déjà réservées
    existing_meeting = current_app.db.meetings.find_one({
        'date': date,
        'time': time,
        'status': 'confirmed'
    })

    if existing_meeting:
        return jsonify({'error': 'Le créneau est déjà réservé.'}), 409

    # Insérer une nouvelle entrée dans la base de données pour bloquer le créneau
    current_app.db.meetings.insert_one({
        'user_id': current_user.id,
        'date': date,
        'time': time,
        'status': 'confirmed'
    })

    return jsonify({'success': 'Créneau bloqué avec succès.'}), 200


@main.route('/admin_calendar')
@login_required
def admin_calendar():
    if current_user.role != 'admin':
        return "Unauthorized", 403

    meetings = current_app.db.meetings.find()
    events = []

    for meeting in meetings:
        user = current_app.db.users.find_one({"_id": ObjectId(meeting['user_id'])})
        if user:  # Vérifie si l'utilisateur a bien été trouvé
            events.append({
                'id': str(meeting['_id']),
                'title': f"{user['prenom']} {user['nom']}",
                'date': meeting['date'],
                'time': meeting['time'],
                'status': meeting['status'],
                'user_id': user['_id']  # Ajout de l'ID du formateur
            })
        else:
            events.append({
                'id': str(meeting['_id']),
                'title': "Utilisateur inconnu",
                'date': meeting['date'],
                'time': meeting['time'],
                'status': meeting['status'],
                'user_id': None  # Pas d'ID utilisateur
            })


    return render_template("fasto/admin_calendar.html", events=events)



# Route pour gérer le profil utilisateur
@main.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        current_user.nom = request.form.get('nom')
        current_user.prenom = request.form.get('prenom')

        # Mise à jour des informations spécifiques aux formateurs ou écoles
        if current_user.role == 'formateur':
            current_user.secteur = request.form.get('secteur')
            current_user.region_habitation = request.form.get('region_habitation')
            competences_input = request.form.get('competences', '')
            current_user.competences = [{'value': comp.strip()} for comp in competences_input.split(',')]
        elif current_user.role == 'ecole':
            current_user.status = request.form.get('status')
            current_user.adresse = request.form.get('adresse')
            current_user.telephone = request.form.get('telephone')

        # Gestion de la mise à jour de la photo de profil

        photo = request.files.get('photo_profil')
        if photo:
            # Obtenir le type de fichier
            file_type = photo.content_type.split('/')[-1]  # Par exemple 'jpeg', 'png'
            encoded_photo = base64.b64encode(photo.read()).decode('utf-8')
            current_user.photo_profil = encoded_photo
            current_user.photo_profil_type = file_type  # Sauvegarder le type de fichier
            print(f"Contenu de l'image base64: {current_user.photo_profil[:100]}...")  # Imprimer les premiers 100 caractères




        current_user.save()
        flash('Profil mis à jour avec succès.', 'success')
        return redirect(url_for('main.profile'))

    competences_str = ', '.join([comp['value'] for comp in current_user.competences]) if current_user.role == 'formateur' else ''
    return render_template('fasto/apps/app-profile.html', user=current_user, competences_str=competences_str)
    
# Route pour afficher le profil d'un utilisateur
@main.route('/view_profile/<user_id>')
@login_required
def view_profile(user_id):
    user = current_app.db.users.find_one({"_id": ObjectId(user_id)})
    if not user:
        flash("Utilisateur non trouvé.", "danger")
        return redirect(url_for('main.admin_calendar'))

    competences_str = ', '.join([comp['value'] for comp in user.get('competences', [])])

    return render_template('fasto/apps/app-profile.html', user=user, competences_str=competences_str)


# Fonction pour envoyer un email
def send_email(subject, sender, recipients, body):
    msg = Message(subject, sender=sender, recipients=recipients)
    msg.body = body
    mail.send(msg)

# Route pour afficher et soumettre le questionnaire pour les écoles
# Route pour la validation du code unique
@main.route('/questionnaire', methods=['GET', 'POST'])
@login_required
def questionnaire():
    if current_user.role != 'ecole':
        flash("Seules les écoles peuvent accéder au questionnaire.", "danger")
        return redirect(url_for("main.index"))

    # Si le code est envoyé (POST), on le valide
    if request.method == 'POST':
        code = request.form.get('code')
        # Vérifier si le code correspond à un formateur
        formateur = current_app.db.users.find_one({'unique_code': code})

        if formateur:
            # Si le code est valide, on redirige vers la même page avec le formateur_id
            return redirect(url_for('main.questionnaire', formateur_id=formateur['_id']))
        else:
            flash('Code invalide. Veuillez réessayer.', 'danger')
    
    # Si le formateur_id est dans l'URL, afficher les actions
    formateur_id = request.args.get('formateur_id')
    code_valid = True if formateur_id else False

    return render_template("fasto/questionnaire.html", code_valid=code_valid, formateur_id=formateur_id)


# Route pour soumettre le questionnaire
@main.route('/submit_questionnaire/<formateur_id>', methods=['POST'])
@login_required
def submit_questionnaire(formateur_id):
    if current_user.role != 'ecole':
        flash("Seules les écoles peuvent soumettre le questionnaire.", "danger")
        return redirect(url_for("main.index"))

    # Récupérer les réponses du questionnaire
    responses = {
        "satisfaction_prestation": request.form.get('satisfaction_prestation'),
        "rappelleriez": request.form.get('rappelleriez'),
        "interaction": request.form.get('interaction'),
        "ponctualite": request.form.get('ponctualite'),
        "recommande": request.form.get('recommande')
    }

    # Vérification si le formateur existe
    formateur = current_app.db.users.find_one({'_id': ObjectId(formateur_id)})
    if not formateur:
        flash("Formateur non trouvé.", "danger")
        return redirect(url_for('main.index'))

    # Sauvegarder les réponses dans la collection `questionnaires` de la base de données
    current_app.db.questionnaires.insert_one({
        "formateur_id": ObjectId(formateur_id),
        "ecole_id": current_user.id,  # Utilisation de l'attribut 'id'
        "responses": responses,
        "timestamp": datetime.now()
    })

    # Envoyer un email avec les réponses du questionnaire et inclure le nom de l'école
    subject = f"Questionnaire de l'école {current_user.ecole} pour {formateur['prenom']} {formateur['nom']}"
    body = f"Voici les réponses du questionnaire pour le formateur {formateur['prenom']} {formateur['nom']} (rempli par l'école {current_user.ecole}) :\n\n" \
           f"Satisfaction prestation : {responses['satisfaction_prestation']}\n" \
           f"Rappelleriez-vous : {responses['rappelleriez']}\n" \
           f"Interaction : {responses['interaction']}\n" \
           f"Ponctualité : {responses['ponctualite']}\n" \
           f"Recommandation : {responses['recommande']}"

    send_email(subject, current_app.config['MAIL_DEFAULT_SENDER'], ['contact@institutdelabelisationfrancais.fr'], body)

    flash('Questionnaire soumis avec succès et rapport envoyé par email.', 'success')
    return redirect(url_for('main.index'))



# Route pour uploader un fichier pour un formateur donné
@main.route('/upload_file/<formateur_id>', methods=['POST'])
@login_required
def upload_file(formateur_id):
    if 'file' not in request.files:
        flash('Aucun fichier sélectionné', 'danger')
        return redirect(url_for('main.questionnaire', formateur_id=formateur_id))
    
    file = request.files['file']
    if file.filename == '':
        flash('Aucun fichier sélectionné', 'danger')
        return redirect(url_for('main.questionnaire', formateur_id=formateur_id))

    if file:
        # Logique d'enregistrement du fichier
        filename = secure_filename(file.filename)
        file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        flash('Fichier envoyé avec succès.', 'success')
        return redirect(url_for('main.index'))
    
    
@main.route('/upload_and_send_email', methods=['POST'])
def upload_and_send_email():
    if 'file' not in request.files:
        flash('Aucun fichier sélectionné', 'danger')
        return redirect(url_for('main.questionnaire'))  
    
    file = request.files['file']
    if file.filename == '':
        flash('Aucun fichier sélectionné', 'danger')
        return redirect(url_for('main.questionnaire'))  

    if file:
        filename = secure_filename(file.filename)
        
        # Préparer l'email
        msg = Message(
            subject="Fichier envoyé par l'utilisateur",
            sender=current_app.config['MAIL_DEFAULT_SENDER'],
            recipients=['contact@institutdelabelisationfrancais.fr']
        )
        msg.body = "Veuillez trouver ci-joint un fichier envoyé par l'utilisateur."
        
        # Attacher le fichier
        file_stream = io.BytesIO(file.read())  # Lire le fichier en mémoire
        msg.attach(filename, file.content_type, file_stream.read())

        try:
            mail.send(msg)
            flash('Email envoyé avec succès.', 'success')
        except Exception as e:
            flash(f'Échec de l\'envoi de l\'email : {str(e)}', 'danger')

    return redirect(url_for('main.questionnaire'))




# Route pour créer une session de paiement avec Stripe
@main.route('/create_checkout_session', methods=['POST'])
@login_required
def create_checkout_session():
    data = request.get_json()
    date = data.get('date')
    time = data.get('time')

    # Validation des données
    if not date or not time:
        return jsonify({'error': 'Date ou heure manquante.'}), 400

    try:
        # Créer la session Stripe avec les méthodes de paiement ajoutées : carte bleue et PayPal
        session = stripe.checkout.Session.create(
            payment_method_types=['card', 'paypal'],  # Ajout de 'paypal' comme méthode de paiement
            line_items=[{
                'price_data': {
                    'currency': 'eur',
                    'product_data': {
                        'name': 'Acompte pour rendez-vous',
                    },
                    'unit_amount': 5000,  # Montant total de 50€
                },
                'quantity': 1,
            }],
            mode='payment',
            success_url=url_for('main.payment_success', _external=True) + '?session_id={CHECKOUT_SESSION_ID}',
            cancel_url=url_for('main.payment_cancel', _external=True),
        )

        # Enregistrer la session Stripe dans la base de données
        current_app.db.meetings.update_one(
            {'user_id': current_user.id, 'date': date, 'time': time},
            {'$set': {'stripe_session_id': session.id, 'status': 'pending'}},
            upsert=True
        )

        return jsonify({'id': session.id})

    except stripe.error.StripeError as e:
        logging.error(f"Erreur Stripe: {e}")
        return jsonify({'error': 'Erreur lors de la création de la session Stripe.'}), 500





# Route pour gérer le succès du paiement
def send_booking_confirmation_email(meeting_id):
    meeting = current_app.db.meetings.find_one({'_id': ObjectId(meeting_id)})
    if not meeting:
        logging.error("Meeting not found for ID: %s", meeting_id)
        return

    formateur = current_app.db.users.find_one({'_id': ObjectId(meeting['user_id'])})
    if not formateur:
        logging.error("Formateur not found for ID: %s", meeting['user_id'])
        return

    subject = "Confirmation de votre rendez-vous"
    body = f"""
    <html>
    <body style="font-family: Arial, sans-serif; line-height: 1.6;">
        <h2 style="color: #2c3e50;">Bonjour {formateur['prenom']} {formateur['nom']},</h2>
        <p style="color: #34495e; font-size: 16px;">
            Votre rendez-vous pour le <strong>{meeting['date']}</strong> à <strong>{meeting['time']}</strong> a bien été confirmé.
            Un acompte de <strong>50€</strong> a été réglé pour ce rendez-vous.
        </p>
        <p style="color: #34495e; font-size: 16px;">
            Veuillez prévoir une durée de deux heures pour cet entretien ainsi qu'une pièce d'identité.
            Durant ce rendez-vous, quelques questions vous seront posées.
        </p>
        <p style="color: #34495e; font-size: 16px;">
            Cordialement,<br/>
            <strong>L'équipe de l'Institut de Labélisation Français</strong>
        </p>
        <hr style="border: 0; height: 1px; background: #e0e0e0; margin-top: 20px; margin-bottom: 20px;">
        <p style="font-size: 12px; color: #95a5a6;">
            Cet email a été généré automatiquement. Merci de ne pas y répondre.
        </p>
    </body>
    </html>
    """

    msg = Message(subject, sender=current_app.config['MAIL_DEFAULT_SENDER'], recipients=[formateur['email']])
    msg.html = body
    logging.info("Attempting to send email to: %s", formateur['email'])
    
    try:
        mail.send(msg)
        logging.info("Email sent successfully to: %s", formateur['email'])
    except Exception as e:
        logging.error("Failed to send email: %s", str(e))

@main.route('/payment_success')
@login_required
def payment_success():
    session_id = request.args.get('session_id')
    session = stripe.checkout.Session.retrieve(session_id)

    # Mettre à jour le statut du rendez-vous dans la base de données
    meeting = current_app.db.meetings.find_one_and_update(
        {'stripe_session_id': session_id},
        {'$set': {'status': 'confirmed'}},
        return_document=True
    )

    if meeting:
        logging.info("Meeting confirmed, sending confirmation email.")
        # Envoyer un email de confirmation au formateur
        send_booking_confirmation_email(meeting['_id'])

    flash("Votre rendez-vous a été confirmé avec succès!", "success")
    return render_template('fasto/payment_success.html')

# Route pour gérer l'annulation du paiement
@main.route('/payment_cancel')
@login_required
def payment_cancel():
    flash("Le paiement a été annulé.", "danger")
    return redirect(url_for('main.calendar'))

@main.route('/delete_appointment/<event_id>', methods=['DELETE'])
@login_required
def delete_appointment(event_id):
    if current_user.role != 'admin':
        return jsonify(success=False, message="Non autorisé"), 403

    if not event_id:
        return jsonify(success=False, message="ID du rendez-vous manquant"), 400

    result = current_app.db.meetings.delete_one({'_id': ObjectId(event_id)})

    if result.deleted_count == 1:
        return jsonify(success=True, message="Rendez-vous annulé avec succès")
    else:
        return jsonify(success=False, message="Erreur lors de l'annulation du rendez-vous"), 500



# Route pour l'autocomplétion des noms d'écoles
@main.route('/autocomplete_schools')
def autocomplete_schools():
    query = request.args.get('query', '')
    if not query:
        return jsonify([])

    schools = current_app.db.schools.find(
        {"Dénomination": {"$regex": query, "$options": "i"}},
        {"_id": 0, "Dénomination": 1}
    ).limit(10)

    suggestions = []
    for school in schools:
        suggestions.append({"label": school["Dénomination"], "value": school["Dénomination"]})
    
    return jsonify(suggestions)

# Route pour afficher le tableau de bord des écoles
@main.route("/ecole_dashboard")
@login_required
def ecole_dashboard():
    formateurs = list(current_app.db.users.find({"role": "formateur"}, {"password_hash": 0}))

    # Récupérer les valeurs uniques pour les filtres
    secteurs = current_app.db.users.distinct("secteur")
    competences = current_app.db.users.distinct("competences.value")
    regions = current_app.db.users.distinct("region_habitation")

    return render_template(
        "fasto/pages/ecole_dashboard.html",
        formateurs=formateurs,
        secteurs=secteurs,
        competences=competences,
        regions=regions,
    )

# Route pour filtrer les formateurs
@main.route('/filter_formateurs', methods=['GET'])
def filter_formateurs():
    nom_prenom = request.args.get('nom_prenom', '')
    secteur = request.args.get('secteur', '')
    region_habitation = request.args.get('region_habitation', '')
    competences = request.args.getlist('competences[]')

    query = {}
    
    if nom_prenom:
        query['$or'] = [
            {'nom': {'$regex': nom_prenom, '$options': 'i'}},
            {'prenom': {'$regex': nom_prenom, '$options': 'i'}}
        ]
    
    if secteur:
        query['secteur'] = secteur
    
    if region_habitation:
        query['region_habitation'] = region_habitation
    
    if competences and competences[0] != '':
        query['competences.value'] = {'$in': competences}

    logging.debug(f"Query: {query}")  # Pour le débogage

    formateurs = list(current_app.db.users.find(query, {'password_hash': 0}))
    
    logging.debug(f"Formateurs trouvés: {formateurs}")  # Pour le débogage
    
    # Convertir ObjectId en chaîne de caractères et transformer les bytes en base64
    for formateur in formateurs:
        formateur['_id'] = str(formateur['_id'])
        if 'photo_profil' in formateur and formateur['photo_profil'] is not None:
            formateur['photo_profil'] = base64.b64encode(formateur['photo_profil']).decode('utf-8')

    return jsonify(formateurs)



# Route pour la gestion de la réinitialisation du mot de passe (formulaire)
@main.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = current_app.db.users.find_one({"email": email})

        if user:
            # Générer un token de réinitialisation
            token = generate_reset_token(user['email'])
            reset_url = url_for('main.reset_password', token=token, _external=True)
            send_reset_email(user['email'], reset_url)
            flash('Un email de réinitialisation a été envoyé à votre adresse email.', 'success')
        else:
            flash('Cet email n\'est pas enregistré.', 'danger')

    return render_template('fasto/pages/page-forgot-password.html')

# Route pour la réinitialisation du mot de passe via le token reçu par email
@main.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        # Vérification du token
        email = confirm_reset_token(token)
    except:
        flash('Le lien de réinitialisation est invalide ou a expiré.', 'danger')
        return redirect(url_for('main.forgot_password'))

    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            flash('Les mots de passe ne correspondent pas.', 'danger')
            return redirect(url_for('main.reset_password', token=token))

        # Mettez à jour le mot de passe dans la base de données
        user = User.get_by_email(email)
        if user:
            user.set_password(password)
            user.save()

        flash('Votre mot de passe a été réinitialisé avec succès.', 'success')
        return redirect(url_for('main.page_login'))

    return render_template('fasto/pages/page-reset-password.html')

def is_valid_name(value):
    return bool(re.match(r"^[A-Za-zÀ-ÿ' -]{2,}$", value))

def is_valid_subject(value):
    return bool(re.match(r"^[A-Za-zÀ-ÿ0-9' -]{3,50}$", value))

def is_valid_message(value):
    return bool(re.match(r"^[A-Za-zÀ-ÿ0-9.,!?()' \n\r-]{5,500}$", value)) and not is_random_text(value)

def is_random_text(value):
    if len(value.split()) < 3:  # Trop court
        return True
    if re.search(r"(\w)\1\1", value):  # Séquences répétées
        return True
    return False

@main.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        nom = request.form.get('nom', '').strip()
        email = request.form.get('email', '').strip()
        sujet = request.form.get('sujet', '').strip()
        message = request.form.get('message', '').strip()

        # Valider chaque champ
        if not is_valid_name(nom):
            flash("Le nom est invalide. Veuillez utiliser uniquement des lettres.", "danger")
            return redirect(url_for('main.contact'))

        if not re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", email):
            flash("L'email est invalide. Veuillez fournir une adresse email valide.", "danger")
            return redirect(url_for('main.contact'))

        if not is_valid_subject(sujet):
            flash("Le sujet est invalide. Évitez les suites de lettres aléatoires.", "danger")
            return redirect(url_for('main.contact'))

        if not is_valid_message(message):
            flash("Le message est invalide. Évitez les suites de lettres aléatoires.", "danger")
            return redirect(url_for('main.contact'))

        # Sauvegarder dans la base de données et envoyer l'email
        contact_message = ContactMessage(nom=nom, email=email, sujet=sujet, message=message)
        contact_message.save()

        email_body = f"Nom: {nom}\nEmail: {email}\n\nMessage:\n{message}"
        send_email(sujet, current_app.config['MAIL_DEFAULT_SENDER'], [current_app.config['MAIL_DEFAULT_SENDER']], email_body)

        flash("Votre message a été envoyé avec succès. Nous vous contacterons bientôt.", "success")
        return redirect(url_for('main.contact'))

    return render_template('fasto/contacts.html')


def send_email(subject, sender, recipients, body):
    msg = Message(subject, sender=sender, recipients=recipients)
    msg.body = body
    mail.send(msg)


@main.route('/charte_conformite', methods=['POST'])
@login_required
def charte_conformite():
    current_user.charte_acceptee = True
    current_user.save()
    flash('Charte acceptée avec succès.', 'success')
    return jsonify(success=True)

def convert_image_to_base64(formateurs):
    for formateur in formateurs:
        if formateur['photo_profil'] is not None:
            # Vérifier le type de données de l'image avant la conversion
            print(f"Type avant conversion pour {formateur['nom']}: {type(formateur['photo_profil'])}")
            
            # Si l'image est déjà en base64 (str), ne rien faire
            if isinstance(formateur['photo_profil'], bytes):
                formateur['photo_profil'] = base64.b64encode(formateur['photo_profil']).decode('utf-8')
            
            # Après conversion
            print(f"Type après conversion pour {formateur['nom']}: {type(formateur['photo_profil'])}")
    
    return formateurs


# Route pour afficher la liste des formateurs
@main.route('/view_formateurs')
def view_formateurs():
    formateurs = list(current_app.db.users.find({"role": {"$regex": "formateur"}}))

    # Convertir les images en base64
    formateurs = convert_image_to_base64(formateurs)

    # Ajouter un cache-buster pour éviter le cache du navigateur
    cache_buster = random.randint(0, 1000000)

    return render_template('fasto/view_formateurs.html', formateurs=formateurs, cache_buster=cache_buster)





@main.route("/admin/generate_code", methods=["POST"])
@login_required
def admin_generate_code():
    if current_user.role != "admin":
        return jsonify(success=False, message="Non autorisé"), 403

    formateur_id = request.form.get("formateur_id")
    if not formateur_id:
        return jsonify(success=False, message="ID du formateur manquant"), 400

    formateur = current_app.db.users.find_one({"_id": ObjectId(formateur_id), "role": {"$regex": "formateur"}})
    if not formateur:
        return jsonify(success=False, message="Formateur non trouvé"), 404

    # Génération du code unique
    code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
    current_app.db.users.update_one({"_id": ObjectId(formateur_id)}, {"$set": {"unique_code": code}})

    # Envoi de l'email avec le code et le modèle à envoyer aux écoles
    subject = "Votre code unique pour le questionnaire"
    
    # Contenu du modèle d'email pour les écoles
    body = f"""
    Bonjour {formateur['prenom']},

    Voici votre code unique : {code}. Utilisez ce code pour permettre aux écoles de vérifier votre profil et remplir le questionnaire.

    Ci-dessous, un modèle d'email que vous pouvez utiliser pour contacter les écoles :

    ---------------------------------------------------
    Objet : Demande de participation à l’évaluation pour ma labellisation LSSP2024

    Bonjour [Nom de la personne ou du responsable de l'école],

    Je me permets de vous contacter dans le cadre de mon processus de labellisation auprès de l'Institut de Labélisation Français (ILF) pour obtenir le label LSSP2024 : Label de Softs Skills Profesionnelles. Actuellement en cours d’évaluation, l’une des étapes indispensables consiste à recueillir des retours d’établissements avec lesquels j’ai collaboré.

    Je vous sollicite donc pour participer à cette démarche en remplissant un court questionnaire, qui permettra de valider mon dossier de labellisation en évaluant la qualité de mes interventions. Votre retour est crucial pour m’aider à obtenir cette certification.

    Afin de faciliter ce processus, un code unique a été généré et vous permettra d’accéder au questionnaire en ligne :

    Votre code unique : {code}

    Voici les étapes à suivre :
        1. Cliquez sur ce lien : [Lien vers le site d'inscription].
        2. Saisissez le code unique dans le champ dédié.
        3. Remplissez le questionnaire, ce qui ne prendra que quelques minutes.

    Je vous remercie sincèrement pour votre participation et votre temps. Vos retours sont un élément essentiel dans ma démarche de labellisation. Si vous avez des questions ou des difficultés pour remplir le questionnaire, je reste à votre disposition pour vous assister.

    Bien cordialement,
    {formateur['prenom']} {formateur['nom']}
    Formateur en cours de labellisation LSSP2024
    [Vos coordonnées]
    ---------------------------------------------------

    Merci de votre coopération.

    Cordialement,
    L'équipe de l'Institut de labélisation français
    """

    send_email(subject, current_app.config['MAIL_DEFAULT_SENDER'], [formateur['email']], body)

    return redirect(url_for('main.admin_dashboard'))



@main.route('/admin/affiliations')
@login_required
def admin_affiliations():
    if current_user.role != 'admin':
        return "Unauthorized", 403

    # Récupérer tous les ambassadeurs et leurs formateurs affiliés
    ambassadors = current_app.db.users.find({"role": "ambassadeur"})

    # Préparer les données pour chaque ambassadeur
    data = []
    for ambassador in ambassadors:
        affiliated_users = current_app.db.users.find({"email": {"$in": ambassador.get("affiliated_users", [])}})
        data.append({
            "ambassador": ambassador,
            "affiliated_users": affiliated_users
        })

    return render_template("fasto/admin_affiliations.html", data=data)

@main.route('/admin_assign_ambassador', methods=['POST'])
@login_required
def admin_assign_ambassador():
    if current_user.role != 'admin':
        return jsonify(success=False, message="Non autorisé"), 403

    formateur_id = request.form.get('formateur_id')
    if not formateur_id:
        return jsonify(success=False, message="ID du formateur manquant"), 400

    # Récupérer le formateur dans la base de données
    formateur = current_app.db.users.find_one({"_id": ObjectId(formateur_id)})
    if not formateur:
        return redirect(url_for('main.admin_dashboard'))

    # Récupérer ou initialiser l'attribut `roles`
    current_role = formateur.get("role","formateur")
    if "ambassadeur" in current_role:
        flash("Ce formateur est déjà ambassadeuur.", "info")
        return redirect(url_for('main.admin_dashboard'))

    updated_role = f"{current_role},ambassadeur" if current_role else "ambassadeur"

    # Générer un code unique pour l'affiliation
    code_affiliation = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))


    # Mettre à jour les rôles et ajouter le code unique
    current_app.db.users.update_one(
        {"_id": ObjectId(formateur_id)},
        {
            "$set": {
                "role": updated_role,
                "unique_code": code_affiliation
            }
        }
    )

    # Envoyer un email ou retourner un message
    flash("Le rôle d'ambassadeur a été ajouté avec succès et le code d'affiliation généré.", "success")
    return redirect(url_for('main.admin_dashboard'))

