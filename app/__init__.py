import os

from flask import Flask
from flask_login import LoginManager

from .database import db
from .models import Users

app = Flask(__name__)

# Configuration
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "default-secret-key")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ECHO"] = True

db.init_app(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message_category = "info"


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


try:
    with app.app_context():
        db.create_all()
except Exception:
    Exception("Error with database: \n 1. Check if the database is running \n 2. Check if the ENV database URL is correct")

# Import your application's routes
