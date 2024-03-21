from flask import flash, redirect, render_template, request, url_for
from flask_login import login_required, login_user, logout_user

from . import app
from .AuthManager import AuthManager
from .database import db
from .models import Users

auth_manager = AuthManager(db)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/home")
@login_required
def home():
    return render_template("home.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        if auth_manager.register(email, password):
            flash("Account created for {}".format(email), "success")
            return redirect("/home")
        else:
            flash("An error occured", "danger")
    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        user = Users.query.filter_by(email=email).first()
        if user and auth_manager.login(email, password):
            login_user(user)
            return redirect("/home")
        else:
            flash("Login Unsuccessful. Please check email and password", "danger")
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))
