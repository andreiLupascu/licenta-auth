import logging

from flask import Flask
from flask_cors import CORS
from flask_jwt_extended import JWTManager

import app.auth as auth


def create_app():
    app = Flask(__name__)
    CORS(app)
    app.config.from_envvar('FLASK_CONFIG_FILE')
    app.logger.setLevel(logging.DEBUG)
    jwt = JWTManager(app)
    from app import auth
    app.register_blueprint(auth.app)
    return app


if __name__ == "__main__":
    create_app().run()
