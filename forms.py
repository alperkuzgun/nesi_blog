from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, EmailField
from wtforms.validators import DataRequired, URL
from flask_ckeditor import CKEditorField

##WTForm
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")

class RegisterForm(FlaskForm):
    email = EmailField ("Your Email Address", validators=[DataRequired()])
    password = PasswordField ("Your Password", validators=[DataRequired()])
    password_check = PasswordField ("Retype Your Password", validators=[DataRequired()])
    name = StringField ("Your User Name", validators=[DataRequired()])
    submit = SubmitField('Sign Me Up')

class LoginForm(FlaskForm):
    email = EmailField ("Your Email Address", validators=[DataRequired()])
    password = PasswordField ("Your Password", validators=[DataRequired()])
    submit = SubmitField('Let me in!')

class CommentForm(FlaskForm):
    comment = CKEditorField("Comment", validators=[DataRequired()])
    submit = SubmitField("Submit Comment")