from flask import Blueprint, request, jsonify, current_app
import base64
from flask_jwt_extended import create_access_token
from passlib.hash import bcrypt
import pymysql
import datetime

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


def verify_credentials(username, password):
    port = int(current_app.config['DB_PORT'])
    conn = pymysql.connect(host=current_app.config['DB_HOST'],
                           port=port,
                           user=current_app.config['DB_USER'],
                           passwd=current_app.config['DB_PASS'],
                           db=current_app.config['DB_NAME'])
    with conn.cursor(pymysql.cursors.DictCursor) as cur:
        try:
            cur.execute('SELECT password FROM user WHERE username = %s;', (username,))
            db_pass = cur.fetchone()['password']
            conn.close()
            return bcrypt.verify(password, db_pass)
        except TypeError:
            conn.close()
            current_app.logger.error("Invalid password.")
