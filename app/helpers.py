import pymysql
from flask import current_app
from passlib.hash import bcrypt


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


def get_connection():
    port = int(current_app.config['DB_PORT'])
    return pymysql.connect(host=current_app.config['DB_HOST'],
                           port=port,
                           user=current_app.config['DB_USER'],
                           passwd=current_app.config['DB_PASS'],
                           db=current_app.config['DB_NAME'])
