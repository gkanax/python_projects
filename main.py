import flask
import werkzeug
from flask_login import LoginManager, login_user, login_required, UserMixin, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, request, send_from_directory, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Integer, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key-goes-here'


# CREATE DATABASE
class Base(DeclarativeBase):
    pass


login_manager = LoginManager()
login_manager.init_app(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(model_class=Base)
db.init_app(app)


# CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(1000))


with app.app_context():
    db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register', methods=["POST", "GET"])
def register():
    error = None
    if request.method == "POST":
        new_user = User(
            name=request.form.get("name"),
            email=request.form.get("email"),
            password=generate_password_hash(request.form.get("password"), method="pbkdf2:sha256", salt_length=8)
        )
        if db.session.execute(db.select(User).where(User.email == new_user.email)):
            error = 'User already exists'
            return render_template("register.html", error=error)
        else:
            db.session.add(new_user)
            db.session.commit()
            # Log in and authenticate user after adding details to database.
            flask.flash('Logged in successfully.')
            login_user(new_user)
            return render_template("secrets.html", name=new_user.name)
    return render_template("register.html")


@app.route('/login', methods=["POST", "GET"])
def login():
    error = None
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Logged in successfully.')
                login_user(user)
                return render_template("secrets.html", name=user.name)
            else:
                error = 'Wrong password for this User'
                return render_template("login.html", error=error)
        else:
            error = 'No matching User'
        return render_template("register.html", error=error)
    return render_template("login.html", error=error)


@app.route('/secrets')
@login_required
def secrets():
    return render_template("secrets.html")


@app.route('/logout')
def logout():
    logout_user()
    print("Logged out")
    return redirect(url_for("home"))


@app.route('/download')
@login_required
def download():
    return send_from_directory('static', path="files/cheat_sheet.pdf", as_attachment=True)


if __name__ == "__main__":
    app.run(debug=True)