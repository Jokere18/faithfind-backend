from flask import Flask, request, jsonify, session
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, date
import psycopg2
import psycopg2.extras
import os
from functools import wraps

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-for-local-testing')
CORS(app, supports_credentials=True)

DATABASE_URL = os.environ.get('DATABASE_URL')

def get_db_connection():
    if DATABASE_URL:
        conn = psycopg2.connect(DATABASE_URL)
        conn.cursor_factory = psycopg2.extras.RealDictCursor
    else:
        import sqlite3
        conn = sqlite3.connect('faithfinds.db')
        conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Check if tables exist
        if DATABASE_URL:
            cursor.execute("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name='users')")
        else:
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
        
        if not cursor.fetchone()[0]:
            print("Setting up database...")
            
            if DATABASE_URL:
                # PostgreSQL table creation
                cursor.execute('''
                CREATE TABLE users (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(255) UNIQUE NOT NULL,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                ''')
                
                cursor.execute('''
                CREATE TABLE events (
                    id SERIAL PRIMARY KEY,
                    title VARCHAR(255) NOT NULL,
                    description TEXT,
                    type VARCHAR(100) NOT NULL,
                    date DATE NOT NULL,
                    time VARCHAR(10),
                    location VARCHAR(255),
                    max_attendees INTEGER,
                    is_volunteer_opportunity BOOLEAN DEFAULT FALSE,
                    volunteer_hours REAL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                ''')
                
                cursor.execute('''
                CREATE TABLE registrations (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER REFERENCES users(id),
                    event_id INTEGER REFERENCES events(id),
                    status VARCHAR(50) DEFAULT 'registered',
                    registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(user_id, event_id)
                )
                ''')
                
                # Insert admin user
                password_hash = generate_password_hash('password')
                cursor.execute('''
                INSERT INTO users (username, email, password_hash) VALUES 
                (%s, %s, %s)
                ''', ('admin', 'admin@faithfinds.com', password_hash))
                
                # Insert sample events
                events = [
                    ("Sunday Morning Worship", "Join us for our weekly worship service with inspiring music and meaningful messages.", "worship", "2025-09-07", "10:00", "Main Sanctuary", 200, False, None),
                    ("Community Food Drive", "Help organize and distribute food to families in need. Volunteers needed for setup and distribution.", "volunteer", "2025-09-14", "09:00", "Fellowship Hall", 30, True, 4.0),
                    ("Bible Study Group", "Weekly Bible study focusing on the Gospel of Matthew. All are welcome!", "study", "2025-09-10", "19:00", "Room 101", 25, False, None),
                    ("Youth Fellowship Night", "Fun activities, games, and fellowship for our youth group (ages 13-18).", "fellowship", "2025-09-12", "18:30", "Youth Center", 40, False, None)
                ]
                
                for event in events:
                    cursor.execute('''
                    INSERT INTO events (title, description, type, date, time, location, max_attendees, is_volunteer_opportunity, volunteer_hours) 
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ''', event)
            else:
                # SQLite table creation (for local development)
                cursor.execute('''
                CREATE TABLE users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                ''')
                
                cursor.execute('''
                CREATE TABLE events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    description TEXT,
                    type TEXT NOT NULL,
                    date DATE NOT NULL,
                    time TEXT,
                    location TEXT,
                    max_attendees INTEGER,
                    is_volunteer_opportunity BOOLEAN DEFAULT 0,
                    volunteer_hours REAL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                ''')
                
                cursor.execute('''
                CREATE TABLE registrations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER REFERENCES users(id),
                    event_id INTEGER REFERENCES events(id),
                    status TEXT DEFAULT "registered",
                    registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(user_id, event_id)
                )
                ''')
                
                # Insert admin user
                password_hash = generate_password_hash('password')
                cursor.execute('''
                INSERT INTO users (username, email, password_hash) VALUES 
                (?, ?, ?)
                ''', ('admin', 'admin@faithfinds.com', password_hash))
                
                # Insert sample events
                events = [
                    ("Sunday Morning Worship", "Join us for our weekly worship service with inspiring music and meaningful messages.", "worship", "2025-09-07", "10:00", "Main Sanctuary", 200, 0, None),
                    ("Community Food Drive", "Help organize and distribute food to families in need. Volunteers needed for setup and distribution.", "volunteer", "2025-09-14", "09:00", "Fellowship Hall", 30, 1, 4.0),
                    ("Bible Study Group", "Weekly Bible study focusing on the Gospel of Matthew. All are welcome!", "study", "2025-09-10", "19:00", "Room 101", 25, 0, None),
                    ("Youth Fellowship Night", "Fun activities, games, and fellowship for our youth group (ages 13-18).", "fellowship", "2025-09-12", "18:30", "Youth Center", 40, 0, None)
                ]
                
                for event in events:
                    cursor.execute('''
                    INSERT INTO events (title, description, type, date, time, location, max_attendees, is_volunteer_opportunity, volunteer_hours) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', event)
            
            conn.commit()
            print("✅ Database created!")
    except Exception as e:
        print(f"Database initialization error: {e}")
    finally:
        conn.close()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        
        conn = get_db_connection()
        user = conn.execute('SELECT username FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        conn.close()
        
        if not user or user['username'] != 'admin':
            return jsonify({'error': 'Admin privileges required'}), 403
        return f(*args, **kwargs)
    return decorated_function

def serialize_event(event):
    """Convert database row to JSON-serializable dict"""
    event_dict = dict(event)
    if event_dict.get('date'):
        try:
            event_dict['date'] = datetime.strptime(event_dict['date'], '%Y-%m-%d').date().isoformat()
        except:
            pass
    if event_dict.get('time'):
        try:
            event_dict['time'] = datetime.strptime(event_dict['time'], '%H:%M').time().isoformat()
        except:
            pass
    return event_dict

# Root route for testing
@app.route('/')
def index():
    return jsonify({
        'message': 'FaithFinds API Server is running! 🙏',
        'status': 'healthy',
        'version': '1.0.0',
        'endpoints': {
            'auth': '/api/auth/*',
            'events': '/api/events',
            'admin': '/api/admin/*'
        }
    })

@app.route('/api/health')
def health():
    return jsonify({'status': 'healthy', 'message': 'API is running'})

# Authentication Routes
@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    
    if not username or not email or not password:
        return jsonify({'error': 'All fields are required'}), 400
    
    password_hash = generate_password_hash(password)
    
    try:
        conn = get_db_connection()
        conn.execute(
            'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
            (username, email, password_hash)
        )
        conn.commit()
        conn.close()
        return jsonify({'message': 'Registration successful'}), 201
    except (psycopg2.IntegrityError, Exception) as e:
        return jsonify({'error': 'Username or email already exists'}), 400

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    
    if user and check_password_hash(user['password_hash'], password):
        session['user_id'] = user['id']
        session['username'] = user['username']
        return jsonify({
            'message': 'Login successful',
            'user': {
                'id': user['id'],
                'username': user['username'],
                'email': user['email'],
                'is_admin': user['username'] == 'admin'
            }
        }), 200
    else:
        return jsonify({'error': 'Invalid username or password'}), 401

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'message': 'Logout successful'}), 200

@app.route('/api/auth/me', methods=['GET'])
@login_required
def get_current_user():
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    conn.close()
    
    if user:
        return jsonify({
            'id': user['id'],
            'username': user['username'],
            'email': user['email'],
            'is_admin': user['username'] == 'admin'
        }), 200
    else:
        return jsonify({'error': 'User not found'}), 404

# Events Routes
@app.route('/api/events', methods=['GET'])
def get_events():
    search = request.args.get('search', '')
    event_type = request.args.get('type', '')
    
    conn = get_db_connection()
    
    query = 'SELECT * FROM events WHERE date >= date("now")'
    params = []
    
    if search:
        query += ' AND (title LIKE ? OR description LIKE ?)'
        params.extend([f'%{search}%', f'%{search}%'])
    
    if event_type:
        query += ' AND type = ?'
        params.append(event_type)
    
    query += ' ORDER BY date ASC'
    
    events = conn.execute(query, params).fetchall()
    conn.close()
    
    return jsonify([serialize_event(event) for event in events]), 200

@app.route('/api/events/<int:event_id>', methods=['GET'])
def get_event(event_id):
    conn = get_db_connection()
    event = conn.execute('SELECT * FROM events WHERE id = ?', (event_id,)).fetchone()
    
    if not event:
        return jsonify({'error': 'Event not found'}), 404
    
    registration_status = None
    if 'user_id' in session:
        registration = conn.execute('SELECT status FROM registrations WHERE event_id = ? AND user_id = ?', 
                                   (event_id, session['user_id'])).fetchone()
        if registration:
            registration_status = registration['status']
    
    conn.close()
    
    event_data = serialize_event(event)
    event_data['registration_status'] = registration_status
    
    return jsonify(event_data), 200

@app.route('/api/events/<int:event_id>/register', methods=['POST'])
@login_required
def register_for_event(event_id):
    try:
        conn = get_db_connection()
        conn.execute(
            'INSERT INTO registrations (user_id, event_id, status) VALUES (?, ?, ?)',
            (session['user_id'], event_id, 'registered')
        )
        conn.commit()
        conn.close()
        return jsonify({'message': 'Successfully registered for event'}), 200
    except (psycopg2.IntegrityError, Exception) as e:
        return jsonify({'error': 'Already registered for this event'}), 400

@app.route('/api/events/<int:event_id>/unregister', methods=['POST'])
@login_required
def unregister_from_event(event_id):
    conn = get_db_connection()
    conn.execute('DELETE FROM registrations WHERE user_id = ? AND event_id = ?', 
               (session['user_id'], event_id))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Successfully unregistered from event'}), 200

# Dashboard Route
@app.route('/api/dashboard', methods=['GET'])
@login_required
def get_dashboard():
    conn = get_db_connection()
    
    events = conn.execute('''
        SELECT e.*, r.status as registration_status 
        FROM events e 
        LEFT JOIN registrations r ON e.id = r.event_id AND r.user_id = ?
        WHERE e.date >= date('now')
        ORDER BY e.date ASC
    ''', (session['user_id'],)).fetchall()
    
    my_events = conn.execute('''
        SELECT e.* FROM events e
        JOIN registrations r ON e.id = r.event_id
        WHERE r.user_id = ? AND e.date >= date('now')
        ORDER BY e.date ASC
    ''', (session['user_id'],)).fetchall()
    
    conn.close()
    
    return jsonify({
        'events': [serialize_event(event) for event in events],
        'my_events': [serialize_event(event) for event in my_events]
    }), 200

# Admin Routes
@app.route('/api/admin/stats', methods=['GET'])
@admin_required
def get_admin_stats():
    conn = get_db_connection()
    
    event_count = conn.execute('SELECT COUNT(*) as count FROM events').fetchone()['count']
    user_count = conn.execute('SELECT COUNT(*) as count FROM users').fetchone()['count']
    registration_count = conn.execute('SELECT COUNT(*) as count FROM registrations').fetchone()['count']
    
    recent_events = conn.execute('''
        SELECT e.*, COUNT(r.id) as registration_count 
        FROM events e 
        LEFT JOIN registrations r ON e.id = r.event_id 
        GROUP BY e.id 
        ORDER BY e.date DESC 
        LIMIT 10
    ''').fetchall()
    
    conn.close()
    
    return jsonify({
        'event_count': event_count,
        'user_count': user_count,
        'registration_count': registration_count,
        'recent_events': [serialize_event(event) for event in recent_events]
    }), 200

@app.route('/api/admin/events', methods=['GET', 'POST'])
@admin_required
def admin_events():
    if request.method == 'POST':
        data = request.get_json()
        
        try:
            conn = get_db_connection()
            conn.execute('''
                INSERT INTO events (title, description, type, date, time, location, 
                                  max_attendees, is_volunteer_opportunity, volunteer_hours)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                data.get('title'),
                data.get('description'),
                data.get('type'),
                data.get('date'),
                data.get('time'),
                data.get('location'),
                int(data.get('max_attendees')) if data.get('max_attendees') else None,
                1 if data.get('is_volunteer_opportunity') else 0,
                float(data.get('volunteer_hours')) if data.get('volunteer_hours') else None
            ))
            conn.commit()
            conn.close()
            return jsonify({'message': 'Event created successfully'}), 201
        except Exception as e:
            return jsonify({'error': str(e)}), 400
    
    else:  # GET
        conn = get_db_connection()
        events = conn.execute('''
            SELECT e.*, COUNT(r.id) as registration_count 
            FROM events e 
            LEFT JOIN registrations r ON e.id = r.event_id 
            GROUP BY e.id 
            ORDER BY e.date DESC
        ''').fetchall()
        conn.close()
        
        return jsonify([serialize_event(event) for event in events]), 200

@app.route('/api/admin/events/<int:event_id>', methods=['GET', 'PUT', 'DELETE'])
@admin_required
def admin_event(event_id):
    conn = get_db_connection()
    
    if request.method == 'GET':
        event = conn.execute('SELECT * FROM events WHERE id = ?', (event_id,)).fetchone()
        conn.close()
        
        if not event:
            return jsonify({'error': 'Event not found'}), 404
        
        return jsonify(serialize_event(event)), 200
    
    elif request.method == 'PUT':
        data = request.get_json()
        
        try:
            conn.execute('''
                UPDATE events SET title = ?, description = ?, type = ?, date = ?, 
                                time = ?, location = ?, max_attendees = ?,
                                is_volunteer_opportunity = ?, volunteer_hours = ?
                WHERE id = ?
            ''', (
                data.get('title'),
                data.get('description'),
                data.get('type'),
                data.get('date'),
                data.get('time'),
                data.get('location'),
                int(data.get('max_attendees')) if data.get('max_attendees') else None,
                1 if data.get('is_volunteer_opportunity') else 0,
                float(data.get('volunteer_hours')) if data.get('volunteer_hours') else None,
                event_id
            ))
            conn.commit()
            conn.close()
            return jsonify({'message': 'Event updated successfully'}), 200
        except Exception as e:
            return jsonify({'error': str(e)}), 400
    
    elif request.method == 'DELETE':
        try:
            conn.execute('DELETE FROM events WHERE id = ?', (event_id,))
            conn.commit()
            conn.close()
            return jsonify({'message': 'Event deleted successfully'}), 200
        except Exception as e:
            return jsonify({'error': str(e)}), 400

if __name__ == '__main__':
    init_db()
    print("Starting FaithFinds API Server...")
    print("Admin Login: username='admin', password='password'")
    print("API running on: http://localhost:5000")
    app.run(debug=True, port=5000)