import os
import sqlite3
import uuid
from datetime import datetime
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, jsonify, g, send_from_directory
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'dpirts-secret-key-2026-secure'
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'database.db')

# ─── Database Helpers ───────────────────────────────────────────────

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row  # Enable column access by name
    db.execute("PRAGMA foreign_keys = ON")
    db.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            phone TEXT,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'citizen',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS issues (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            category TEXT NOT NULL,
            priority TEXT DEFAULT 'Medium',
            location TEXT NOT NULL,
            description TEXT NOT NULL,
            image_path TEXT,
            status TEXT DEFAULT 'Submitted',
            user_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            issue_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (issue_id) REFERENCES issues(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS status_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            issue_id INTEGER NOT NULL,
            old_status TEXT,
            new_status TEXT NOT NULL,
            changed_by INTEGER NOT NULL,
            note TEXT,
            changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (issue_id) REFERENCES issues(id),
            FOREIGN KEY (changed_by) REFERENCES users(id)
        );
    ''')

    # Seed admin user if not exists or update name if wrong
    admin = db.execute('SELECT id, name FROM users WHERE email = ?', ('admin@dpirts.gov',)).fetchone()
    if not admin:
        db.execute(
            'INSERT INTO users (name, email, phone, password_hash, role) VALUES (?, ?, ?, ?, ?)',
            ('Admin User', 'admin@dpirts.gov', '0000000000',
             generate_password_hash('admin123'), 'admin')
        )
        db.commit()
    elif admin['name'] != 'Admin User':
         db.execute('UPDATE users SET name = ? WHERE email = ?', ('Admin User', 'admin@dpirts.gov'))
         db.commit()
    db.close()

# ─── Auth Decorators ────────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page.', 'warning')
            return redirect(url_for('login'))
        if session.get('role') != 'admin':
            flash('Admin access required.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ─── Context Processor ──────────────────────────────────────────────

@app.context_processor
def inject_user():
    user = None
    if 'user_id' in session:
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    return dict(current_user=user)

# ─── Public Routes ──────────────────────────────────────────────────

@app.route('/')
def index():
    db = get_db()
    total_issues = db.execute('SELECT COUNT(*) FROM issues').fetchone()[0]
    resolved = db.execute("SELECT COUNT(*) FROM issues WHERE status IN ('Resolved', 'Closed')").fetchone()[0]
    in_progress = db.execute("SELECT COUNT(*) FROM issues WHERE status = 'In Progress'").fetchone()[0]
    total_users = db.execute('SELECT COUNT(*) FROM users WHERE role = ?', ('citizen',)).fetchone()[0]
    recent_issues = db.execute(
        'SELECT i.*, u.name as reporter_name FROM issues i JOIN users u ON i.user_id = u.id ORDER BY i.created_at DESC LIMIT 6'
    ).fetchall()
    return render_template('index.html',
        total_issues=total_issues, resolved=resolved,
        in_progress=in_progress, total_users=total_users,
        recent_issues=recent_issues)

# ─── Auth Routes ────────────────────────────────────────────────────

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        phone = request.form.get('phone', '').strip()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')

        if not all([name, email, password]):
            flash('All fields are required.', 'danger')
            return redirect(url_for('register'))
        if password != confirm:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('register'))
        if len(password) < 6:
            flash('Password must be at least 6 characters.', 'danger')
            return redirect(url_for('register'))

        db = get_db()
        existing = db.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone()
        if existing:
            flash('Email already registered.', 'danger')
            return redirect(url_for('register'))

        db.execute(
            'INSERT INTO users (name, email, phone, password_hash) VALUES (?, ?, ?, ?)',
            (name, email, phone, generate_password_hash(password))
        )
        db.commit()
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')

        db = get_db()
        user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()

        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['user_name'] = user['name']
            session['role'] = user['role']
            flash(f'Welcome back, {user["name"]}!', 'success')
            if user['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password.', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

# ─── User Dashboard ─────────────────────────────────────────────────

@app.route('/dashboard')
@login_required
def dashboard():
    db = get_db()
    user_id = session['user_id']
    issues = db.execute(
        'SELECT * FROM issues WHERE user_id = ? ORDER BY created_at DESC', (user_id,)
    ).fetchall()
    total = len(issues)
    submitted = sum(1 for i in issues if i['status'] == 'Submitted')
    under_review = sum(1 for i in issues if i['status'] == 'Under Review')
    in_progress = sum(1 for i in issues if i['status'] == 'In Progress')
    resolved = sum(1 for i in issues if i['status'] in ('Resolved', 'Closed'))
    return render_template('dashboard.html',
        issues=issues, total=total, submitted=submitted,
        under_review=under_review, in_progress=in_progress, resolved=resolved)

# ─── Admin Dashboard ────────────────────────────────────────────────

@app.route('/admin')
@admin_required
def admin_dashboard():
    db = get_db()
    issues = db.execute(
        'SELECT i.*, u.name as reporter_name FROM issues i JOIN users u ON i.user_id = u.id ORDER BY i.created_at DESC'
    ).fetchall()
    total = len(issues)
    submitted = sum(1 for i in issues if i['status'] == 'Submitted')
    under_review = sum(1 for i in issues if i['status'] == 'Under Review')
    in_progress = sum(1 for i in issues if i['status'] == 'In Progress')
    resolved = sum(1 for i in issues if i['status'] in ('Resolved', 'Closed'))
    total_users = db.execute('SELECT COUNT(*) FROM users WHERE role = ?', ('citizen',)).fetchone()[0]
    return render_template('admin.html',
        issues=issues, total=total, submitted=submitted,
        under_review=under_review, in_progress=in_progress,
        resolved=resolved, total_users=total_users)

# ─── Issue Routes ───────────────────────────────────────────────────

@app.route('/report', methods=['GET', 'POST'])
@login_required
def report_issue():
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        category = request.form.get('category', '').strip()
        priority = request.form.get('priority', 'Medium').strip()
        location = request.form.get('location', '').strip()
        description = request.form.get('description', '').strip()

        if not all([title, category, location, description]):
            flash('Please fill in all required fields.', 'danger')
            return redirect(url_for('report_issue'))

        image_path = None
        if 'image' in request.files:
            file = request.files['image']
            if file and file.filename and allowed_file(file.filename):
                ext = file.filename.rsplit('.', 1)[1].lower()
                filename = f"{uuid.uuid4().hex}.{ext}"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                image_path = f"uploads/{filename}"

        db = get_db()
        cursor = db.execute(
            '''INSERT INTO issues (title, category, priority, location, description, image_path, user_id)
               VALUES (?, ?, ?, ?, ?, ?, ?)''',
            (title, category, priority, location, description, image_path, session['user_id'])
        )
        issue_id = cursor.lastrowid

        # Add initial status history
        db.execute(
            'INSERT INTO status_history (issue_id, old_status, new_status, changed_by, note) VALUES (?, ?, ?, ?, ?)',
            (issue_id, None, 'Submitted', session['user_id'], 'Issue reported by citizen')
        )
        db.commit()

        flash('Issue reported successfully! Track your issue from the dashboard.', 'success')
        return redirect(url_for('issue_detail', issue_id=issue_id))

    return render_template('report.html')

@app.route('/issues')
def issues_list():
    db = get_db()
    query = 'SELECT i.*, u.name as reporter_name FROM issues i JOIN users u ON i.user_id = u.id WHERE 1=1'
    params = []

    status = request.args.get('status')
    category = request.args.get('category')
    priority = request.args.get('priority')
    search = request.args.get('search', '').strip()

    if status:
        query += ' AND i.status = ?'
        params.append(status)
    if category:
        query += ' AND i.category = ?'
        params.append(category)
    if priority:
        query += ' AND i.priority = ?'
        params.append(priority)
    if search:
        query += ' AND (i.title LIKE ? OR i.description LIKE ? OR i.location LIKE ?)'
        params.extend([f'%{search}%'] * 3)

    query += ' ORDER BY i.created_at DESC'
    issues = db.execute(query, params).fetchall()

    return render_template('issues.html', issues=issues,
        current_status=status, current_category=category,
        current_priority=priority, current_search=search)

@app.route('/issue/<int:issue_id>')
def issue_detail(issue_id):
    db = get_db()
    issue = db.execute(
        'SELECT i.*, u.name as reporter_name, u.email as reporter_email FROM issues i JOIN users u ON i.user_id = u.id WHERE i.id = ?',
        (issue_id,)
    ).fetchone()

    if not issue:
        flash('Issue not found.', 'danger')
        return redirect(url_for('issues_list'))

    comments = db.execute(
        'SELECT c.*, u.name as author_name, u.role as author_role FROM comments c JOIN users u ON c.user_id = u.id WHERE c.issue_id = ? ORDER BY c.created_at ASC',
        (issue_id,)
    ).fetchall()

    history = db.execute(
        'SELECT sh.*, u.name as changed_by_name FROM status_history sh JOIN users u ON sh.changed_by = u.id WHERE sh.issue_id = ? ORDER BY sh.changed_at ASC',
        (issue_id,)
    ).fetchall()

    return render_template('issue_detail.html', issue=issue, comments=comments, history=history)

# ─── API Routes ─────────────────────────────────────────────────────

@app.route('/api/issue/<int:issue_id>/status', methods=['POST'])
@admin_required
def update_issue_status(issue_id):
    db = get_db()
    issue = db.execute('SELECT * FROM issues WHERE id = ?', (issue_id,)).fetchone()
    if not issue:
        return jsonify({'error': 'Issue not found'}), 404

    new_status = request.form.get('status') or request.json.get('status')
    note = request.form.get('note', '') or request.json.get('note', '')

    if not new_status:
        return jsonify({'error': 'Status is required'}), 400

    old_status = issue['status']
    db.execute('UPDATE issues SET status = ?, updated_at = ? WHERE id = ?',
               (new_status, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), issue_id))
    db.execute(
        'INSERT INTO status_history (issue_id, old_status, new_status, changed_by, note) VALUES (?, ?, ?, ?, ?)',
        (issue_id, old_status, new_status, session['user_id'], note)
    )
    db.commit()
    return jsonify({'success': True, 'old_status': old_status, 'new_status': new_status})

@app.route('/api/issue/<int:issue_id>/comment', methods=['POST'])
@login_required
def add_comment(issue_id):
    db = get_db()
    issue = db.execute('SELECT * FROM issues WHERE id = ?', (issue_id,)).fetchone()
    if not issue:
        return jsonify({'error': 'Issue not found'}), 404

    content = request.form.get('content', '').strip()
    if not content:
        return jsonify({'error': 'Comment cannot be empty'}), 400

    db.execute(
        'INSERT INTO comments (issue_id, user_id, content) VALUES (?, ?, ?)',
        (issue_id, session['user_id'], content)
    )
    db.commit()

    user = db.execute('SELECT name, role FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    return jsonify({
        'success': True,
        'comment': {
            'author_name': user['name'],
            'author_role': user['role'],
            'content': content,
            'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
    })

@app.route('/api/issue/<int:issue_id>/delete', methods=['POST'])
@admin_required
def delete_issue(issue_id):
    db = get_db()
    issue = db.execute('SELECT * FROM issues WHERE id = ?', (issue_id,)).fetchone()
    if not issue:
        return jsonify({'error': 'Issue not found'}), 404

    # Delete related records
    db.execute('DELETE FROM comments WHERE issue_id = ?', (issue_id,))
    db.execute('DELETE FROM status_history WHERE issue_id = ?', (issue_id,))
    db.execute('DELETE FROM issues WHERE id = ?', (issue_id,))
    db.commit()

    # Remove image if exists
    if issue['image_path']:
        img_path = os.path.join(app.config['UPLOAD_FOLDER'], os.path.basename(issue['image_path']))
        if os.path.exists(img_path):
            os.remove(img_path)

    return jsonify({'success': True})

@app.route('/api/stats')
def get_stats():
    db = get_db()
    total = db.execute('SELECT COUNT(*) FROM issues').fetchone()[0]
    by_status = {}
    for row in db.execute('SELECT status, COUNT(*) as count FROM issues GROUP BY status').fetchall():
        by_status[row['status']] = row['count']
    by_category = {}
    for row in db.execute('SELECT category, COUNT(*) as count FROM issues GROUP BY category').fetchall():
        by_category[row['category']] = row['count']
    return jsonify({'total': total, 'by_status': by_status, 'by_category': by_category})

# ─── Initialize & Run ──────────────────────────────────────────────

if __name__ == '__main__':
    init_db()
    # Use 8080 to avoid conflict with default Flask port or other services
    app.run(debug=True, port=8080)
