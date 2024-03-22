from flask import flash, redirect, render_template, request, jsonify
from . import app
from .AuthManager import AuthManager
from .database import db
from .models import Users

auth_manager = AuthManager(db)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    try:
        if request.method == "POST":
            requestStep = request.form.get("requestStep")
            username = request.form.get("username")
            if requestStep == "1":
                # Placeholder: Implement the logic for OPRF step 1
                pass
            elif requestStep == "2":
                # Placeholder: Implement the logic for AKE step, involves client public key handling
                pass
            else:
                flash("Invalid request")
                return redirect("/signup")
        return render_template("signup.html")
    except Exception as e:
        print(e)
        flash("An error occurred during signup")
        return redirect("/signup")


@app.route("/login", methods=["GET", "POST"])
def login():
    try:
        if request.method == "POST":
            requestStep = request.form.get("requestStep")
            username = request.form.get("username")
            if requestStep == "1":
                # Placeholder: Implement the logic for OPRF step 1
                pass
            elif requestStep == "2":
                # Placeholder: Implement the logic for AKE step
                pass
            else:
                flash("Invalid request")
                return redirect("/login")
        return render_template("login.html")
    except Exception as e:
        print(e)
        flash("An error occurred during login")
        return redirect("/login")
