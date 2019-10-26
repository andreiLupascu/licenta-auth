from flask import Flask, request, jsonify
import base64
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
)
from passlib.hash import bcrypt
import pymysql
import logging
app = Flask(__name__)
app.config.from_envvar('FLASK_CONFIG_FILE')
app.logger.setLevel(logging.DEBUG)

jwt = JWTManager(app)

#TODO maybe change JWT expiration payload
@app.route('/api/auth/login', methods=['POST'])
def login():
    credentials = request.json.get('credentials')
    decoded_credentials = base64.b64decode(credentials).decode("utf-8")
    username = decoded_credentials.split(':', 1)[0]
    password = decoded_credentials.split(':', 1)[1]
    if verify_credentials(username, password):
        token = {
            'access_token': create_access_token(identity=username),
        }
        app.logger.info('%s has logged in.', username)
        return jsonify(token), 200
    else:
        app.logger.info('%s has tried to log in.', username)
        return jsonify({"msg": "Bad username or password"}), 400


def verify_credentials(username, password):
    port = int(app.config['DB_PORT'])
    conn = pymysql.connect(host=app.config['DB_HOST'],
                           port=port,
                           user=app.config['DB_USER'],
                           passwd=app.config['DB_PASS'],
                           db=app.config['DB_NAME'])
    with conn.cursor(pymysql.cursors.DictCursor) as cur:
        try:
            cur.execute('SELECT * FROM Users WHERE username = %s;', (username,))
            db_pass = cur.fetchone()['Password']
            cur.close()
            conn.close()
            return bcrypt.verify(password, db_pass)
        except TypeError:
            app.logger.error("Invalid password.")

if __name__ == '__main__':
    app.run()
