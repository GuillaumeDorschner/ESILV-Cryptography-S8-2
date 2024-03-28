from flask import Blueprint, flash, jsonify, redirect, render_template, request
import logging

from .AuthManager import AuthManager
from .database import db
from .models import Users
import base64

# added logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

site = Blueprint("simple_page", __name__, template_folder="templates")
auth_manager = AuthManager(db)

global p, q
p = 0
q = 0

@site.route("/")
def index():
    return render_template("index.html")


@site.route("/signup", methods=["POST", "GET"])
def signup():

    #adding a database clearing for test purposes 
    #otherwise it was redirecting to the same page non stop
    db.session.query(Users).delete()
    db.session.commit()

    try:
        data = request.json
        if data is None:
            flash("Invalid request")
            return redirect("/signup")
        request_step = data.get("request_step")
        username = data.get("username")
        if request_step == 1:
            # Placeholder: Implement the logic for oprf
            if Users.query.filter_by(username=username).first() is not None:
                flash("User already exists")
                return redirect("/signup")

            oprf_begin = data.get("oprf_begin")

            oprf_key = auth_manager.generate_user_key()

            user = {
                "username": username,
                "oprf_key": oprf_key,
            }

            db.session.add(Users(**user))
            db.session.commit()

            oprf = auth_manager.perform_oprf(oprf_begin, user["oprf_key"])

            return jsonify(
                {"oprf": oprf, "server_public_key": auth_manager.server_public_key}
            )
        elif request_step == 2:
            # Placeholder: Implement the logic save the encrypted envelope
            encrypted_envelope = data.get("encrypted_envelope")
            client_public_key = data.get("client_public_key")

            user = Users.query.filter_by(username=username).first()
            user.encrypted_envelope = encrypted_envelope
            user.client_public_key = client_public_key

            db.session.commit()

            return jsonify({"message": "Signup successful"})
        else:
            logging.warning("Received non-POST request on /signup")
            flash("Invalid request")
            return redirect("/signup")
    except Exception as e:
        logging.error(f"An error occurred: {e}", exc_info=True)
        flash("An error occurred during signup")
        return redirect("/signup")

@site.route("/login", methods=["POST"])
def login():
    try:
        data = request.json
        if data is None:
            flash("Invalid request")
            return redirect("/login")

        username = data.get("username")
        oprf_begin = data.get("oprf_begin")

        user = Users.query.filter_by(username=username).first()

        if user is None:
            flash("User not found")
            return redirect("/login")

        oprf = auth_manager.perform_oprf(oprf_begin, user["oprf_key"])

        return jsonify({"oprf": oprf, "encrypted_envelope": user["encrypted_envelope"]})
    except Exception as e:
        print(e)
        flash("An error occurred during login")
        return redirect("/login")


@site.route("/AKE", methods=["POST"])
def AKE():
    try:
        auth_manager.clear_shared_key()
        data = request.json
        if data is None:
            flash("Invalid request")
            return redirect("/login")

        # username = data.get("username")
        client_public_key = data.get("client_public_key")
        shared_key = auth_manager.AKE(client_public_key)
        print(
            "The following shared_key should be the same on the server and the client: ",
            shared_key,
        )

        return jsonify({"message": "AKE successful"})
    except Exception as e:
        print(e)
        flash("An error occurred during signup")
        return redirect("/login")


# @site.route("/chat", methods=["GET", "POST"])
# def chat():
#     try:
#         if request.method == "POST":
#             data = request.json
#             if data is None:
#                 flash("Invalid request")
#                 return redirect("/login")
#             secret = data.get("secrect")
#             encrypted_message = data.get("message")
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
