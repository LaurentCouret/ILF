from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from flask import current_app
from bson.objectid import ObjectId
import logging
from datetime import datetime

class User(UserMixin):
    def __init__(self, nom, prenom, email, password, role, secteur=None, competences=None, region_habitation=None, status=None, telephone=None, ecole=None, adresse=None, email_confirmed=False, photo_profil=None, label_obtained_date=None, email_sent=False, unique_code=None, charte_acceptee=False):
        self.nom = nom
        self.prenom = prenom
        self.secteur = secteur
        self.competences = competences if competences else []
        self.region_habitation = region_habitation
        self.status = status
        self.email = email
        self.password_hash = generate_password_hash(password) if password else ''
        self.telephone = telephone
        self.ecole = ecole
        self.adresse = adresse
        self.role = role
        self.email_confirmed = email_confirmed
        self.photo_profil = photo_profil
        self.label_obtained_date = label_obtained_date if label_obtained_date else datetime.now()
        self.email_sent = email_sent
        self.unique_code = unique_code
        self.charte_acceptee = charte_acceptee  # Correctement assigné ici

    def save(self):
        user_data = {
            "nom": self.nom,
            "prenom": self.prenom,
            "secteur": self.secteur,
            "competences": self.competences,
            "region_habitation": self.region_habitation,
            "status": self.status,
            "email": self.email,
            "password_hash": self.password_hash,
            "telephone": self.telephone,
            "ecole": self.ecole,
            "adresse": self.adresse,
            "role": self.role,
            "email_confirmed": self.email_confirmed,
            "photo_profil": self.photo_profil,
            "label_obtained_date": self.label_obtained_date,
            "email_sent": self.email_sent,
            "unique_code": self.unique_code,
            "charte_acceptee": self.charte_acceptee  # Inclus dans la sauvegarde
        }
        current_app.db.users.update_one({"email": self.email}, {"$set": user_data}, upsert=True)
        logging.debug(f"Utilisateur sauvegardé : {user_data}")

    @staticmethod
    def get_by_email(email):
        user_data = current_app.db.users.find_one({"email": email})
        if user_data:
            return User.from_db(user_data)
        return None

    @staticmethod
    def from_db(user_data):
        user = User(
            nom=user_data['nom'],
            prenom=user_data['prenom'],
            email=user_data['email'],
            password='',  
            role=user_data['role'],
            secteur=user_data.get('secteur'),
            competences=user_data.get('competences', []),
            region_habitation=user_data.get('region_habitation'),
            status=user_data.get('status'),
            telephone=user_data.get('telephone'),
            ecole=user_data.get('ecole'),
            adresse=user_data.get('adresse'),
            email_confirmed=user_data.get('email_confirmed', False),
            photo_profil=user_data.get('photo_profil'),
            label_obtained_date=user_data.get('label_obtained_date', datetime.now()),
            email_sent=user_data.get('email_sent', False),
            unique_code=user_data.get('unique_code'),
            charte_acceptee=user_data.get('charte_acceptee', False)  # Ajout de ce champ ici
        )
        user.password_hash = user_data['password_hash']  
        user.id = str(user_data['_id'])
        return user

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        logging.debug(f"Vérification du mot de passe pour {self.email}")
        logging.debug(f"Hash stocké : {self.password_hash}")
        result = check_password_hash(self.password_hash, password)
        logging.debug(f"Résultat de la vérification : {result}")
        return result


class ContactMessage:
    def __init__(self, nom, email, sujet, message, date_envoye=None):
        self.nom = nom
        self.email = email
        self.sujet = sujet
        self.message = message
        self.date_envoye = date_envoye if date_envoye else datetime.now()

    def save(self):
        message_data = {
            "nom": self.nom,
            "email": self.email,
            "sujet": self.sujet,
            "message": self.message,
            "date_envoye": self.date_envoye,
        }
        current_app.db.contact_messages.insert_one(message_data)
