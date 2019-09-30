# website/app.py
import os
from flask import Flask
from .routes import bp
from .models import db
from .oauth2 import config_oauth

def create_app(config=None):
    app = Flask(__name__)

    # load app sepcified configuration
    if config is not None:
        if isinstance(config, dict):
            app.config.update(config)
        elif config.endswith('.py'):
            app.config.from_pyfile(config)
    setup_app(app)
    return app

def setup_app(app):
    db_path = os.path.abspath(os.getcwd()) + "/database.db"
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + db_path
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Create tables if they do not exist already
    @app.before_first_request
    def create_tables():
        db.create_all()

    db.init_app(app)
    config_oauth(app)
    app.register_blueprint(bp, url_prefix='')
