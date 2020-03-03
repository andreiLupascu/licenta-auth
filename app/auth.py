import base64
import datetime

from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import create_access_token

from app.helpers import verify_credentials

app = Blueprint("auth", __name__, url_prefix="")


@app.route('/api/auth', methods=['POST'])
def login():
    credentials = request.json.get('credentials')
    decoded_credentials = base64.b64decode(credentials).decode("utf-8")
    username = decoded_credentials.split(':', 1)[0]
    password = decoded_credentials.split(':', 1)[1]
    expires = datetime.timedelta(days=5)
    if verify_credentials(username, password):
        token = {
            'access_token': create_access_token(identity=username, expires_delta=expires),
        }
        current_app.logger.info('%s has logged in.', username)
        return jsonify(token), 200
    else:
        current_app.logger.info('%s has tried to log in.', username)
        return jsonify({"msg": "Bad username or password"}), 400




