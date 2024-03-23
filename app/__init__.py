import os

from flask import Flask

from .routes import site


from .database import db

app = Flask(__name__)
app.register_blueprint(site)


app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "default-secret-key")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ECHO"] = True

db.init_app(app)

try:
    with app.app_context():
        db.create_all()
except Exception:
    Exception("Error with database: \n 1. Check if the database is running \n 2. Check if the ENV database URL is correct")
