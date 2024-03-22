from .database import db


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    encrypted_envelope = db.Column(db.Text, nullable=False)
    oprf_key = db.Column(db.Text, nullable=False)
