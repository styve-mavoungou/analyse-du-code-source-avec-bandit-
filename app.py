from flask import Flask, render_template, url_for, flash, redirect, request
from flask_login import LoginManager, login_user, current_user, logout_user, login_required
from config import Config
from forms import RegistrationForm, LoginForm, StudentForm
from models import db, User, CLASSES, FILIERES
from functools import wraps

app = Flask(__name__)
app.config.from_object(Config)

# Initialisation DB
db.init_app(app)

# Gestion login
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Créer l'admin par défaut
with app.app_context():
    db.create_all()
    if not User.query.filter_by(is_admin=True).first():
        admin = User(
            username='admin',
            email='admin@example.com',
            first_name='Admin',
            last_name='User',
            class_level='M2',
            filiere='Informatique',
            is_admin=True
        )
        admin.set_password('adminpassword')
        db.session.add(admin)
        db.session.commit()
        print("✅ Admin créé : admin / adminpassword")

# Décorateur admin
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash("Accès réservé aux administrateurs.", "danger")
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

# ------------------ ROUTES ------------------

@app.route("/")
@app.route("/home")
def home():
    return render_template("home.html", title="Accueil")

@app.route("/inscription", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(
            username=form.username.data,
            email=form.email.data,
            first_name=form.first_name.data,
            last_name=form.last_name.data,
            class_level=form.class_level.data,
            filiere=form.filiere.data
        )
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash("Compte créé avec succès ! Connectez-vous.", "success")
        return redirect(url_for('login'))
    return render_template("inscription.html", title="Inscription", form=form)

@app.route("/connexion", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            flash(f"Bienvenue {user.first_name} !", "success")
            return redirect(url_for('home'))
        else:
            flash("Nom d'utilisateur ou mot de passe invalide.", "danger")
    return render_template("connexion.html", title="Connexion", form=form)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Vous êtes déconnecté.", "info")
    return redirect(url_for('home'))

@app.route("/etudiants")
def students():
    # ✅ Version corrigée
    if current_user.is_authenticated:
        # Utilisateur connecté : voir tous les étudiants avec tous les champs
        users = User.query.order_by(User.last_name.asc()).all()
        title = "Liste de tous les étudiants"
    else:
        # Utilisateur non connecté : voir tous les étudiants mais seulement les infos de base
        users = User.query.order_by(User.last_name.asc()).all()
        title = "Liste des étudiants - Connectez-vous pour plus de détails"
    return render_template("etudiants.html", title=title, users=users, CLASSES=CLASSES, FILIERES=FILIERES)

# === AJOUTER ÉTUDIANT ===
@app.route("/ajouter", methods=['GET', 'POST'])
@admin_required
def ajouter_etudiants():
    form = StudentForm()
    if form.validate_on_submit():
        user = User(
            username=form.username.data,
            email=form.email.data,
            first_name=form.first_name.data,
            last_name=form.last_name.data,
            class_level=form.class_level.data,
            filiere=form.filiere.data,
            is_admin=form.is_admin.data
        )
        user.set_password("motdepasseinitial")
        db.session.add(user)
        db.session.commit()
        flash("Étudiant ajouté avec succès !", "success")
        return redirect(url_for("students"))
    return render_template("ajouter_etudiants.html", title="Ajouter un étudiant", form=form, legend="Ajouter un étudiant")

# === MODIFIER ÉTUDIANT ===
@app.route("/modifier/<int:user_id>", methods=['GET', 'POST'])
@admin_required
def modifier_etudiants(user_id):
    user = User.query.get_or_404(user_id)
    form = StudentForm(obj=user, original_username=user.username, original_email=user.email)
    if form.validate_on_submit():
        user.first_name = form.first_name.data
        user.last_name = form.last_name.data
        user.username = form.username.data
        user.email = form.email.data
        user.class_level = form.class_level.data
        user.filiere = form.filiere.data
        user.is_admin = form.is_admin.data
        db.session.commit()
        flash("Étudiant mis à jour avec succès !", "success")
        return redirect(url_for("students"))
    return render_template("modifier_etudiants.html", title="Modifier un étudiant", form=form, legend="Modifier un étudiant")

# === SUPPRIMER ÉTUDIANT ===
@app.route("/supprimer/<int:user_id>", methods=['POST'])
@admin_required
def delete_student(user_id):
    user = User.query.get_or_404(user_id)
    if user.is_admin and User.query.filter_by(is_admin=True).count() == 1:
        flash("Impossible de supprimer le seul administrateur.", "danger")
        return redirect(url_for("students"))
    db.session.delete(user)
    db.session.commit()
    flash("Étudiant supprimé avec succès !", "success")
    return redirect(url_for("students"))

# === PROFIL ===
@app.route("/profil")
@login_required
def profil():
    return render_template("etudiants.html", title="Mon profil", users=[current_user], CLASSES=CLASSES, FILIERES=FILIERES)

# === ADMIN PANEL ===
@app.route("/admin")
@admin_required
def admin_panel():
    return render_template("admin.html", title="Administration")

# ------------------ MAIN ------------------
if __name__ == "__main__":
    app.run(debug=True)
