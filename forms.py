from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from models import User, CLASSES, FILIERES

class RegistrationForm(FlaskForm):
    first_name = StringField('Prénom', validators=[DataRequired(), Length(min=2, max=50)])
    last_name = StringField('Nom', validators=[DataRequired(), Length(min=2, max=50)])
    username = StringField('Nom d\'utilisateur', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    class_level = SelectField('Classe', choices=CLASSES, validators=[DataRequired()])
    filiere = SelectField('Filière', choices=FILIERES, validators=[DataRequired()])
    password = PasswordField('Mot de passe', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirmer le mot de passe', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('S\'inscrire')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Ce nom d\'utilisateur est déjà pris.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Cet email est déjà enregistré.')

class LoginForm(FlaskForm):
    username = StringField('Nom d\'utilisateur', validators=[DataRequired()])
    password = PasswordField('Mot de passe', validators=[DataRequired()])
    submit = SubmitField('Se connecter')

class StudentForm(FlaskForm):
    first_name = StringField('Prénom', validators=[DataRequired(), Length(min=2, max=50)])
    last_name = StringField('Nom', validators=[DataRequired(), Length(min=2, max=50)])
    username = StringField('Nom d\'utilisateur', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    class_level = SelectField('Classe', choices=CLASSES, validators=[DataRequired()])
    filiere = SelectField('Filière', choices=FILIERES, validators=[DataRequired()])
    is_admin = BooleanField('Est administrateur')
    submit = SubmitField('Enregistrer')

    def __init__(self, original_username=None, original_email=None, *args, **kwargs):
        super(StudentForm, self).__init__(*args, **kwargs)
        self.original_username = original_username
        self.original_email = original_email

    def validate_username(self, username):
        if username.data != self.original_username:
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError('Ce nom d\'utilisateur est déjà pris.')

    def validate_email(self, email):
        if email.data != self.original_email:
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError('Cet email est déjà enregistré.')
