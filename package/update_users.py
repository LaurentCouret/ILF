import logging
from pymongo import MongoClient
from werkzeug.security import generate_password_hash
import datetime

def insert_user():
    # Configurer le logging pour enregistrer les erreurs
    logging.basicConfig(filename='insert_user.log', level=logging.ERROR)

    # Connexion à MongoDB
    client = MongoClient('mongodb://localhost:27017/')
    db = client['ILF']

    # Définir l'utilisateur
    user = {
        "nom": "Blanc",
        "prenom": "Marie",
        "email": "marie@gmail.com",
        "password_hash": generate_password_hash("root"),  # Remplacez par le vrai mot de passe
        "role": "formateur",
        "email_confirmed": True,
        "photo_profil": None,  # Base64 image would be handled here if available
        "region_habitation": "Alpes maritimes",
        "secteur": "Informatique",
        "status": "Valider",
        "label_obtained_date": datetime.datetime(2024, 7, 24, 18, 34, 29, 350000),  # Date example from image
        "unique_code": "YYZFD458D",
        "adresse": None,
        "charte_acceptee": True
    }

    # Insérer l'utilisateur dans la collection 'users'
    try:
        db.users.insert_one(user)
        logging.info("Utilisateur inséré avec succès.")
    except Exception as e:
        logging.error(f"Erreur d'insertion pour l'utilisateur {user['prenom']} {user['nom']}: {e}")

if __name__ == "__main__":
    insert_user()
