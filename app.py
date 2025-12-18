from flask import (
    Flask,
    render_template,
    redirect,
    url_for,
    flash,
    abort,
    session,
    request,
    jsonify,
)
from flask_wtf.csrf import CSRFProtect
from models import db, Note, User
from forms import NoteForm, RegisterForm, LoginForm
from dotenv import load_dotenv
from sqlalchemy import text
import os

# ---------------------------
# БАЗОВАЯ КОНФИГУРАЦИЯ
# ---------------------------

load_dotenv()

app = Flask(__name__)

SECRET_KEY = os.getenv("FLASK_SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("FLASK_SECRET_KEY is not set in environment")

DB_URI = os.getenv("FLASK_SQLALCHEMY_DATABASE_URI", "sqlite:///notes.db")

app.config.update(
    SECRET_KEY=SECRET_KEY,
    SQLALCHEMY_DATABASE_URI=DB_URI,
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,  # для продакшена по HTTPS
)

db.init_app(app)
csrf = CSRFProtect(app)


# ---------------------------
# АУТЕНТИФИКАЦИЯ (БЕЗОПАСНАЯ)
# ---------------------------

@app.route("/register", methods=["GET", "POST"])
def register():
    """Регистрация нового пользователя."""
    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(username=form.username.data).first():
            flash("Пользователь с таким именем уже существует.", "danger")
        else:
            user = User(
                username=form.username.data,
                # В рамках ПР4 пароль оставляем в открытом виде (для демонстрации SQL-инъекций).
                password=form.password.data,
            )
            db.session.add(user)
            db.session.commit()
            flash("Регистрация прошла успешно. Теперь можно войти.", "success")
            return redirect(url_for("login"))
    return render_template("register.html", form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    """
    БЕЗОПАСНАЯ версия входа.

    Используются параметризованные запросы SQLAlchemy (text + параметры),
    поэтому пользовательский ввод не интерпретируется как SQL-код.
    """
    form = LoginForm()
    error = None

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        stmt = text(
            "SELECT id, username FROM users "
            "WHERE username = :username AND password = :password "
            "LIMIT 1;"
        )
        result = db.session.execute(stmt, {"username": username, "password": password})
        row = result.first()

        if row:
            session["user_id"] = row.id
            session["username"] = row.username
            flash("Вход выполнен (безопасная версия).", "success")
            return redirect(url_for("index"))
        else:
            error = "Неверный логин или пароль."

    return render_template("login_safe.html", form=form, error=error)


@app.route("/logout")
def logout():
    """Выход пользователя."""
    session.clear()
    flash("Вы вышли из аккаунта.", "info")
    return redirect(url_for("login"))


@app.route("/api/login_check")
def login_check_safe():
    """
    Безопасный эндпоинт для проверки SQLMap.

    Используются параметризованные запросы, поэтому SQL-инъекция невозможна.
    """
    username = request.args.get("username", "")
    password = request.args.get("password", "")

    stmt = text(
        "SELECT id, username FROM users "
        "WHERE username = :username AND password = :password "
        "LIMIT 1;"
    )
    result = db.session.execute(stmt, {"username": username, "password": password})
    row = result.first()

    if row:
        return jsonify({"status": "ok", "user": row.username})
    return jsonify({"status": "fail"})


# ---------------------------
# ЗАМЕТКИ
# ---------------------------

@app.route("/")
def index():
    """Главная страница: список заметок и форма добавления."""
    notes = Note.query.order_by(Note.created_at.desc()).all()
    form = NoteForm()
    username = session.get("username")
    return render_template("index.html", notes=notes, form=form, username=username)


@app.route("/add_note", methods=["POST"])
def add_note():
    """Добавление новой заметки."""
    form = NoteForm()
    if form.validate_on_submit():
        new_note = Note(
            title=form.title.data,
            content=form.content.data,
        )
        db.session.add(new_note)
        db.session.commit()

        # Имитация контроля доступа (IDOR) через сессии:
        note_ids = session.get("note_ids", [])
        if new_note.id not in note_ids:
            note_ids.append(new_note.id)
        session["note_ids"] = note_ids

        flash("Заметка успешно добавлена.", "success")
    else:
        flash("Ошибка при добавлении заметки. Проверьте ввод.", "danger")
    return redirect(url_for("index"))


def _check_note_access(note_id: int) -> Note:
    """Проверка прав доступа к заметке (имитация защиты от IDOR)."""
    note = Note.query.get_or_404(note_id)

    note_ids = session.get("note_ids", [])
    if note.id not in note_ids:
        abort(403)
    return note


@app.route("/edit_note/<int:note_id>", methods=["GET", "POST"])
def edit_note(note_id):
    """Редактирование заметки."""
    note = _check_note_access(note_id)

    form = NoteForm(obj=note)
    if form.validate_on_submit():
        note.title = form.title.data
        note.content = form.content.data
        db.session.commit()
        flash("Заметка успешно обновлена.", "success")
        return redirect(url_for("index"))

    return render_template("edit.html", form=form, note=note)


@app.route("/delete_note/<int:note_id>", methods=["POST"])
def delete_note(note_id):
    """Удаление заметки."""
    note = _check_note_access(note_id)
    db.session.delete(note)
    db.session.commit()
    flash("Заметка удалена.", "info")
    return redirect(url_for("index"))


# ---------------------------
# ЗАГОЛОВКИ БЕЗОПАСНОСТИ
# ---------------------------

@app.after_request
def add_security_headers(response):
    # CSP
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' https://cdn.jsdelivr.net; "
        "script-src 'self' https://cdn.jsdelivr.net; "
        "img-src 'self' data:; "
        "frame-ancestors 'none'; "
        "form-action 'self'; "
        "base-uri 'self'"
    )

    # Clickjacking
    response.headers["X-Frame-Options"] = "DENY"

    # MIME-sniffing
    response.headers["X-Content-Type-Options"] = "nosniff"

    # Referrer policy
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    # HSTS (для HTTPS-развёртывания)
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

    # Маскируем информацию о сервере
    response.headers["Server"] = "SecureNotesApp"

    return response


# ---------------------------
# ТОЧКА ВХОДА
# ---------------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()

    # Небезопасно: отладка включена и слушаем все интерфейсы
    app.run(host="0.0.0.0", port=5000, debug=True)
