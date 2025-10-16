from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin

db = SQLAlchemy()

# Définition des choix pour la classe et la filière
CLASSES = [
    ('L1', 'Licence 1'),
    ('L2', 'Licence 2'),
    ('L3', 'Licence 3'),
    ('M1', 'Master 1'),
    ('M2', 'Master 2')
]

FILIERES = [
    ('Informatique', 'Informatique'),
    ('Genie Logiciel', 'Génie Logiciel'),
    ('Reseaux', 'Réseaux et Télécoms'),
    ('Cybersecurite', 'Cybersécurité')
]

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    class_level = db.Column(db.String(10), nullable=False)
    filiere = db.Column(db.String(50), nullable=False)
    date_registered = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}', Admin={self.is_admin})"
