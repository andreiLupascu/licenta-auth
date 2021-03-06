import base64
import datetime

from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity

from app.helpers import create_jwt_payload, update_password

app = Blueprint("auth", __name__, url_prefix="")


@app.route('/api/auth', methods=['POST'])
def login():
    """
        Login endpoint
        ---
        parameters:
          - name:
            in: body
            required: true
            schema:
                id:
                properties:
                    credentials:
                        type: string
                        example: username:password encoded to base64
        responses:
          200:
            description: returns json with JWT in the access_token field
            schema:
                id:
                properties:
                    access_token:
                        type: string
          400:
            description: returns error message
            schema:
                id:
                properties:
                    msg:
                        type: string
    """
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
    """
            Roles per user endpoint
            This endpoint expects Authorization header set to -Bearer \"token\"- and returns the roles for that user
            ---
            parameters:
              - name: authorization
                in: headers
                type: string
                required: true
                schema:
                    id:
                    properties:
                        authorization:
                            type: string
            responses:
              200:
                description: roles for given user
                schema:
                    id:
                    properties:
                        roles:
                            type: string
                            enum:
                                    - ADMINISTRATOR
                                    - PROGRAM_COMMITTEE
                                    - USER
                            example: [ADMINISTRATOR, PROGRAM_COMMITTEE]
        """
    current_user = get_jwt_identity()
    return jsonify({"roles": current_user['roles']}), 200


@app.route("/api/auth", methods=['PUT'])
@jwt_required
def change_password():
    msg, status_code = update_password(request.json, get_jwt_identity())
    return jsonify({"msg": msg}), status_code
