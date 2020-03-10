import base64
import datetime

from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity

from app.helpers import create_jwt_payload

app = Blueprint("auth", __name__, url_prefix="")


@app.route('/api/auth', methods=['POST'])
def login():
    credentials = request.json.get('credentials')
    decoded_credentials = base64.b64decode(credentials).decode("utf-8")
    username = decoded_credentials.split(':', 1)[0]
    password = decoded_credentials.split(':', 1)[1]
    expires = datetime.timedelta(days=5)
    try:
        payload = create_jwt_payload(username, password)
        token = {
            'access_token': create_access_token(identity=payload, expires_delta=expires),
        }
        current_app.logger.info('%s has logged in.', username)
        return jsonify(token), 200
    except PermissionError:
        return jsonify({"msg": "Bad username or password"}), 400


@app.route("/api/auth", methods=['GET'])
@jwt_required
def get_user_permissions():
    current_user = get_jwt_identity()
    return jsonify({"roles": current_user['roles']}), 200
