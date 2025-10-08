from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
import hashlib
import os
from datetime import datetime, timedelta
import jwt

app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = 'your-secret-key-here'

# Инициализация базы данных
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  password_hash TEXT NOT NULL,
                  email TEXT UNIQUE NOT NULL,
                  gold INTEGER DEFAULT 1000,
                  energy INTEGER DEFAULT 100,
                  keys INTEGER DEFAULT 5,
                  mine_level INTEGER DEFAULT 1,
                  energy_gen_level INTEGER DEFAULT 1,
                  castle_level INTEGER DEFAULT 1,
                  owned_characters TEXT DEFAULT '["white_guy"]',
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    conn.commit()
    conn.close()

# Хеширование пароля
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Генерация JWT токена
def generate_token(user_id, username):
    payload = {
        'user_id': user_id,
        'username': username,
        'exp': datetime.utcnow() + timedelta(days=7)
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

# Проверка JWT токена
def verify_token(token):
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')
    
    if not username or not password or not email:
        return jsonify({'error': 'Все поля обязательны для заполнения'}), 400
    
    if len(password) < 6:
        return jsonify({'error': 'Пароль должен содержать минимум 6 символов'}), 400
    
    password_hash = hash_password(password)
    
    try:
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)',
                 (username, password_hash, email))
        user_id = c.lastrowid
        conn.commit()
        conn.close()
        
        token = generate_token(user_id, username)
        return jsonify({
            'message': 'Регистрация успешна',
            'token': token,
            'user': {
                'id': user_id,
                'username': username,
                'gold': 1000,
                'energy': 100,
                'keys': 5
            }
        }), 201
        
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Пользователь с таким именем или email уже существует'}), 400
    except Exception as e:
        return jsonify({'error': 'Ошибка сервера'}), 500

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'error': 'Все поля обязательны для заполнения'}), 400
    
    password_hash = hash_password(password)
    
    try:
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE username = ? AND password_hash = ?',
                 (username, password_hash))
        user = c.fetchone()
        conn.close()
        
        if user:
            token = generate_token(user[0], user[1])
            return jsonify({
                'message': 'Вход выполнен успешно',
                'token': token,
                'user': {
                    'id': user[0],
                    'username': user[1],
                    'gold': user[4],
                    'energy': user[5],
                    'keys': user[6]
                }
            }), 200
        else:
            return jsonify({'error': 'Неверное имя пользователя или пароль'}), 401
            
    except Exception as e:
        return jsonify({'error': 'Ошибка сервера'}), 500

@app.route('/save_game', methods=['POST'])
def save_game():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'error': 'Токен отсутствует'}), 401
    
    user_data = verify_token(token.replace('Bearer ', ''))
    if not user_data:
        return jsonify({'error': 'Неверный токен'}), 401
    
    data = request.get_json()
    user_id = user_data['user_id']
    
    try:
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('''UPDATE users SET 
                    gold = ?, energy = ?, keys = ?, mine_level = ?, 
                    energy_gen_level = ?, castle_level = ?, owned_characters = ?
                    WHERE id = ?''',
                 (data['gold'], data['energy'], data['keys'], data['mine_level'],
                  data['energy_gen_level'], data['castle_level'], 
                  str(data['owned_characters']), user_id))
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'Игра сохранена'}), 200
        
    except Exception as e:
        return jsonify({'error': 'Ошибка сохранения'}), 500

@app.route('/load_game', methods=['GET'])
def load_game():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'error': 'Токен отсутствует'}), 401
    
    user_data = verify_token(token.replace('Bearer ', ''))
    if not user_data:
        return jsonify({'error': 'Неверный токен'}), 401
    
    user_id = user_data['user_id']
    
    try:
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE id = ?', (user_id,))
        user = c.fetchone()
        conn.close()
        
        if user:
            import ast
            return jsonify({
                'gold': user[4],
                'energy': user[5],
                'keys': user[6],
                'mine_level': user[7],
                'energy_gen_level': user[8],
                'castle_level': user[9],
                'owned_characters': ast.literal_eval(user[10]) if user[10] else ['white_guy']
            }), 200
        else:
            return jsonify({'error': 'Пользователь не найден'}), 404
            
    except Exception as e:
        return jsonify({'error': 'Ошибка загрузки'}), 500

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'OK'}), 200

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
