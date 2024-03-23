from flask import flash, jsonify, redirect, render_template, request, Blueprint
from .AuthManager import AuthManager
from .database import db
from .models import Users


site = Blueprint('simple_page', __name__, template_folder='templates')

auth_manager = AuthManager(db)


@site.route("/")
def index():
    return render_template("index.html")


@site.route("/signup", methods=["POST"])
def signup():
    try:
        if request.method == "POST":
            request_step = request.form.get("request_step")
            username = request.form.get("username")
            if request_step == "1":
                # Placeholder: Implement the logic for oprf

                if Users.query.filter_by(username=username).first() is not None:
                    flash("User already exists")
                    return redirect("/signup")

                oprf_begin = request.form.get("oprf_begin")

                # generate user-specific key
                oprf_key = auth_manager.generate_user_key()

                user = {
                    "username": username,
                    "oprf_key": oprf_key,
                }

                db.session.add(Users(**user))
                db.session.commit()

                oprf = auth_manager.perform_oprf(oprf_begin, user.oprf_key)

                return jsonify(
                    {"oprf": oprf, "server_public_key": auth_manager.server_public_key}
                )
            elif request_step == "2":
                # Placeholder: Implement the logic save the encrypted envelope
                encrypted_envelope = request.form.get("encrypted_envelope")
                client_public_key = request.form.get("client_public_key")

                user = Users.query.filter_by(username=username).first()
                user.encrypted_envelope = encrypted_envelope
                user.client_public_key = client_public_key

                db.session.commit()

                return jsonify({"message": "Signup successful"})
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


@site.route("/login", methods=["POST"])
def login():
    try:
        if request.method == "POST":
            username = request.form.get("username")
            oprf_begin = request.form.get("oprf_begin")

            user = Users.query.filter_by(username=username).first()

            if user is None:
                flash("User not found")
                return redirect("/login")

            oprf = auth_manager.perform_oprf(oprf_begin, user.oprf_key)

            return jsonify(
                {"oprf": oprf, "encrypted_envelope": user.encrypted_envelope}
            )
        else:
            flash("Invalid request")
            return redirect("/login")
    except Exception as e:
        print(e)
        flash("An error occurred during login")
        return redirect("/login")


@site.route("/AKE", methods=["POST"])
def AKE():
    try:
        auth_manager.clear_secrect()
        if request.method == "POST":
            username = request.form.get("username")
            client_public_key = request.form.get("client_public_key")
            shared_key = auth_manager.AKE(client_public_key)
            print(
                "The following shared_key should be the same on the server and the client: ",
                shared_key,
            )

            return jsonify({"message": "AKE successful"})
        else:
            flash("Invalid request")
            return redirect("/login")
    except Exception as e:
        print(e)
        flash("An error occurred during signup")
        return redirect("/login")


# @site.route("/chat", methods=["GET", "POST"])
# def chat():
#     try:
#         if request.method == "POST":
#             secret = request.form.get("secrect")
#             encrypted_message = request.form.get("message")
# # not like that because the user don't send the shared key (use for encryption) the login should be with something else
#             # auth_manager.login_required(secret)

#             message = auth_manager.decrypt_data(encrypted_message)

#             print("Message received: ", message)
#         else:
#             flash("Invalid request")
#             return redirect("/login")
#     except Exception as e:
#         print(e)
#         flash("An error occurred during signup")
#         return redirect("/login")
