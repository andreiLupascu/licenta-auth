import base64

import pymysql
from flask import current_app
from passlib.hash import bcrypt


def get_user_roles(username):
    conn = get_connection()
    with conn.cursor(pymysql.cursors.DictCursor) as cur:
        try:
            roles = []
            cur.execute(
                'SELECT title FROM role WHERE id in ( SELECT role_id FROM conference_user_role cur WHERE '
                'cur.user_id = ( SELECT id FROM user WHERE username = %s));',
                (username,))
            roles_dictionary = cur.fetchall()
            for role in roles_dictionary:
                roles.append(role['title'])
            conn.close()
            return roles
        except TypeError:
            conn.close()
            current_app.logger.error("User has no roles")
            raise PermissionError


def create_jwt_payload(username, password):
    if verify_credentials(username, password):
        roles = get_user_roles(username)
        payload = {
            "user": username,
            "roles": roles
        }
        return payload
    else:
        raise PermissionError


def verify_credentials(username, password):
    conn = get_connection()
    with conn.cursor(pymysql.cursors.DictCursor) as cur:
        try:
            cur.execute('SELECT password FROM user WHERE username = %s;', (username,))
            db_pass = cur.fetchone()['password']
            conn.close()
            return bcrypt.verify(password, db_pass)
        except TypeError:
            conn.close()
            current_app.logger.error("Invalid password.")
            return False


def update_password(request, jwt_identity):
    print(jwt_identity)
    email = request.get('email')
    if jwt_identity.get('user') != email:
        return "Unauthorized request.", 401
    new_password = bcrypt.encrypt(base64.b64decode(request.get('new_password')).decode("utf-8"))
    old_password = base64.b64decode(request.get('old_password')).decode('utf-8')
    conn = get_connection()
    with conn.cursor(pymysql.cursors.DictCursor) as cur:
        try:
            cur.execute('SELECT password FROM user WHERE username = %s;', (email,))
            db_pass = cur.fetchone()['password']
            if bcrypt.verify(old_password, db_pass):
                cur.execute('UPDATE user SET password = %s WHERE username = %s;', (new_password, email,))
                conn.commit()
                conn.close()
                return "", 204
            else:
                return "Invalid credentials", 400
        except Exception as e:
            print(e)
            conn.close()
            return "Something went wrong with the query.", 500

def get_connection():
    port = int(current_app.config['DB_PORT'])
    return pymysql.connect(host=current_app.config['DB_HOST'],
                           port=port,
                           user=current_app.config['DB_USER'],
                           passwd=current_app.config['DB_PASS'],
                           db=current_app.config['DB_NAME'])
