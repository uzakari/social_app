from flask_wtf import Form, RecaptchaField
from wtforms import StringField, PasswordField, BooleanField, SubmitField, TextAreaField, SelectField, ValidationError
from wtforms.validators import DataRequired, Email,Length, Regexp, EqualTo
from model import User, Role
from flask_pagedown.fields import PageDownField


class LoginForm(Form):
    email = StringField('Email', [DataRequired(), Length(1, 64), Email()])
    password = PasswordField('Password', [DataRequired()])
    remember_me = BooleanField('Keep me logged in')
    submit = SubmitField('Log In')
    recaptcha = RecaptchaField()


class RegistrationForm(Form):
    email = StringField('Email', validators=[DataRequired(), Length(max=50), Email()])
    userName = StringField('Username', validators=[DataRequired(), Length(min=1, max=64),
                           Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0, 'Username must have only letters')])
    password = PasswordField('Password', validators=[DataRequired(), EqualTo('confirmedP', message='password must match')])
    confirmedP = PasswordField('Confirm password', validators=[DataRequired()])
    submit = SubmitField('Register')


    def validate_email(self, feild):
        if User.query.filter_by(email=feild.data).first():
            raise ValidationError('Email already registered')


    def validate_userName(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Username already in use')

#edit form

class EditProfileForm(Form):
    name = StringField('Real name', validators=[Length(min=0, max=64)])
    location = StringField('Location ', validators=[Length(min=0, max=64)])
    about_me = TextAreaField('About Me')
    submit = SubmitField('Submit')


class EditProfileAdminForm(Form):
    email = StringField('Email', validators=[DataRequired(), Length(min=1, max=64), Email()])

    username = StringField('Username', validators=[DataRequired(), Length(1, 64), Regexp('^[A-Za-z][A-Za-z0-9]*$', 0, 'Username must be laters only' 'numbers, dots or underscores')])
    
    confimed = BooleanField('Confirm')
    
    role = SelectField('Role', coerce=int)
    
    name = StringField('Real name', validators=[Length(0, 64)])
    
    location = StringField('Location', validators=[Length(0, 65)])
    
    about_me = TextAreaField('About me')
    
    submit = SubmitField('Submit')


    def __init__(self, user, *args, **kwargs):
        super(EditProfileAdminForm, self).__init__(*args, **kwargs)
        self.role.choices = [(role.id, role.name) for role in Role.query.order_by(Role.name).all()]
        self.user = user

    def validate_email(self, field):
        if field.data != self.user.email and User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered')
    
    def validate_username(self, field):
        if field.data != self.username and User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already in use.')
    
      
class PostForm(Form):
    body = PageDownField('Whats on your mind?', validators=[DataRequired()])
    submit = SubmitField('Submit')


class CommentForm(Form):
    body = StringField('', validators=[DataRequired()])
    submit = SubmitField('Submit')