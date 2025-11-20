from flask import Flask, request, jsonify, g
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import os

DB_PATH = 'ctf.db'
app = Flask(__name__)
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = False

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    password_hash TEXT NOT NULL,
                    balance INTEGER NOT NULL
                )''')
    c.execute('''CREATE TABLE IF NOT EXISTS tokens (
                    token TEXT PRIMARY KEY,
                    username TEXT NOT NULL
                )''')
    conn.commit()
    cur = conn.cursor()
    cur.execute('SELECT username FROM users WHERE username = ?', ('admin',))
    if cur.fetchone() is None:
        cur.execute('INSERT INTO users (username, password_hash, balance) VALUES (?, ?, ?)',
                    ('admin', generate_password_hash('REDACTED'), 10000))
        conn.commit()
    conn.close()

if not os.path.exists(DB_PATH):
    init_db()

def create_token_for(username):
    token = str(uuid.uuid4())
    db = get_db()
    db.execute('INSERT INTO tokens (token, username) VALUES (?, ?)', (token, username))
    db.commit()
    return token

def username_for_token(token):
    db = get_db()
    cur = db.execute('SELECT username FROM tokens WHERE token = ?', (token,))
    row = cur.fetchone()
    return row['username'] if row else None

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json(force=True)
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'error': 'username and password required'}), 400
    db = get_db()
    try:
        db.execute('INSERT INTO users (username, password_hash, balance) VALUES (?, ?, ?)',
                   (username, generate_password_hash(password), 100))
        db.commit()
        return jsonify({'ok': True}), 201
    except sqlite3.IntegrityError:
        return jsonify({'error': 'username exists'}), 400

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json(force=True)
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'error': 'username and password required'}), 400
    db = get_db()
    cur = db.execute('SELECT password_hash FROM users WHERE username = ?', (username,))
    row = cur.fetchone()
    if not row or not check_password_hash(row['password_hash'], password):
        return jsonify({'error': 'invalid credentials'}), 401
    token = create_token_for(username)
    return jsonify({'token': token})

@app.route('/api/balance', methods=['GET'])
def balance():
    auth = request.headers.get('Authorization', '')
    token = None
    if auth.startswith('Bearer '):
        token = auth.split(None, 1)[1]
    
    auth_user = username_for_token(token) if token else None
    
    target = request.args.get('username')
    db = get_db()

    if target and target != auth_user:
        return jsonify({'error': 'unauthorized'}), 403

    query_target = request.args.getlist('username')
    if query_target:
        actual_target = query_target[-1]
        cur = db.execute('SELECT username, balance FROM users WHERE username = ?', (actual_target,))
    else:
        if not auth_user:
            return jsonify({'error': 'missing or invalid token'}), 401
        cur = db.execute('SELECT username, balance FROM users WHERE username = ?', (auth_user,))

    row = cur.fetchone()
    if not row:
        return jsonify({'error': 'user not found'}), 404

    resp = {'username': row['username'], 'balance': row['balance']}
    if row['balance'] >= 10000:
        resp['flag'] = 'trustctf{REDACTED}'
    return jsonify(resp)

if __name__ == '__main__':
    app.run(debug=True)




