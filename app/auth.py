from flask import Flask, request, jsonify
import os
import base64
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
)
from passlib.hash import bcrypt
import pymysql

app = Flask(__name__)

app.config['JWT_SECRET_KEY'] = os.getenv('APP_SECRET_KEY')
app.config['DB-HOST'] = os.getenv('APP_DB_HOST')
app.config['DB-PORT'] = os.getenv('APP_DB_PORT')
app.config['DB-USER'] = os.getenv('APP_DB_USER')
app.config['DB-NAME'] = os.getenv('APP_DB_NAME')
app.config['DB-PASS'] = os.getenv('APP_DB_PASS')
jwt = JWTManager(app)


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
        return jsonify(token), 200
    else:
        return jsonify({"msg": "Bad username or password"}), 400


def verify_credentials(username, password):
    port = int(app.config['DB-PORT'])
    conn = pymysql.connect(host=app.config['DB-HOST'],
                           port=port,
                           user=app.config['DB-USER'],
                           passwd=app.config['DB-PASS'],
                           db=app.config['DB-NAME'])
    with conn.cursor(pymysql.cursors.DictCursor) as cur:
        cur.execute('SELECT * FROM Users WHERE username = %s;', (username,))
        db_pass = cur.fetchone()['Password']
        cur.close()
        conn.close()
        return bcrypt.verify(password, db_pass)


if __name__ == '__main__':
    app.run()
