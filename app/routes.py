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
                # Placeholder: Implement the logic for OPRF
                OPRF_Begin = request.form.get("OPRF_Begin")

                # generate user-specific key
                oprf_key = auth_manager.generate_user_key()

                user = {
                    "username": username,
                    "oprf_key": oprf_key,
                    # "encrypted_envelope": "encrypted_envelope_placeholder",
                }

                db.session.add(Users(**user))
                db.session.commit()

                OPRF = auth_manager.perform_oprf(OPRF_Begin, user.oprf_key)

                return jsonify({"OPRF": OPRF})
            elif requestStep == "2":
                # Placeholder: Implement the logic save the encrypted envelope
                encrypted_envelope = request.form.get("encrypted_envelope")
                public_key = request.form.get("public_key")

                user = Users.query.filter_by(username=username).first()
                user.encrypted_envelope = encrypted_envelope
                user.public_key = public_key

                db.session.commit()

            else:
                flash("Invalid request")
                return redirect("/signup")
        else:
            flash("Invalid request")
            return redirect("/signup")
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
            OPRF_Begin = request.form.get("OPRF_Begin")

            user = Users.query.filter_by(username=username).first()

            if user is None:
                flash("User not found")
                return redirect("/login")

            OPRF = auth_manager.perform_oprf(OPRF_Begin, user.oprf_key)

            return jsonify({"OPRF": OPRF, "encrypted_envelope": user.encrypted_envelope})
        else:
            flash("Invalid request")
            return redirect("/login")
    except Exception as e:
        print(e)
        flash("An error occurred during login")
        return redirect("/login")


@app.route("/AKE", methods=["GET", "POST"])
def AKE():
    try:
        if request.method == "POST":
            requestStep = request.form.get("requestStep")
            username = request.form.get("username")
            if requestStep == "1":
                pass
            elif requestStep == "2":
                pass
            else:
                flash("Invalid request")
                return redirect("/signup")
        else:
            flash("Invalid request")
            return redirect("/login")
    except Exception as e:
        print(e)
        flash("An error occurred during signup")
        return redirect("/login")
