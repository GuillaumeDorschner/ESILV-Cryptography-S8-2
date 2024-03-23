from .database import db


class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    oprf_key = db.Column(db.LargeBinary, nullable=False)
    encrypted_envelope = db.Column(db.LargeBinary, nullable=True)
    client_public_key = db.Column(db.LargeBinary, nullable=True)
