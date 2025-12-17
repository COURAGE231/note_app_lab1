from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Length


class NoteForm(FlaskForm):
    title = StringField(
        "Заголовок",
        validators=[
            DataRequired(message="Поле 'Заголовок' обязательно."),
            Length(min=1, max=100, message="Длина заголовка 1–100 символов."),
        ],
    )
    content = TextAreaField(
        "Содержание",
        validators=[
            DataRequired(message="Поле 'Содержание' обязательно."),
        ],
    )
    submit = SubmitField("Сохранить")


class RegisterForm(FlaskForm):
    username = StringField(
        "Имя пользователя",
        validators=[
            DataRequired(),
            Length(min=3, max=50),
        ],
    )
    password = PasswordField(
        "Пароль",
        validators=[
            DataRequired(),
            Length(min=4, max=128),
        ],
    )
    submit = SubmitField("Зарегистрироваться")


class LoginForm(FlaskForm):
    username = StringField("Имя пользователя", validators=[DataRequired()])
    password = PasswordField("Пароль", validators=[DataRequired()])
    submit = SubmitField("Войти")
