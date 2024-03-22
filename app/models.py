from flask_login import UserMixin

from .database import db


class Users(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    # warning we had a lot of trouble with the password field
    password = db.Column(db.LargeBinary)  # password: hachage + salt + cryptage
