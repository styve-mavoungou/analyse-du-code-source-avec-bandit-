import os
from dotenv import load_dotenv

load_dotenv() # Charge les variables d'environnement du fichier .env

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'une_cle_secrete_par_defaut_si_non_trouvee'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///site.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
