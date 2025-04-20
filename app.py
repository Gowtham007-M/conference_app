from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Database connection function
def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

# Initialize the database schema
def init_db():
    conn = get_db_connection()
    with open('schema.sql') as f:
        conn.executescript(f.read())
    conn.commit()
    conn.close()

# Route for the home page (redirect to login)
@app.route('/')
def index():
    return redirect(url_for('login'))

# Register new user
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']

        hashed_pw = generate_password_hash(password)
        conn = get_db_connection()
        try:
            conn.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                         (username, hashed_pw, role))
            conn.commit()
        except sqlite3.IntegrityError:
            flash("Username already taken.")
            return redirect(url_for('register'))
        conn.close()
        flash("Registered successfully! Please log in.")
        return redirect(url_for('login'))

    return render_template('register.html')

# User login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()

        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            flash("Logged in successfully.")
            if user['role'] == 'organizer':
                return redirect(url_for('dashboard_organizer'))
            else:
                return redirect(url_for('dashboard_attendee'))
        else:
            flash("Invalid credentials.")
    return render_template('login.html')

# Create a conference for organizers
@app.route('/organizer/conferences', methods=['GET', 'POST'])
def create_conference():
    if session.get('role') != 'organizer':
        return redirect(url_for('login'))

    conn = get_db_connection()

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        date = request.form['date']
        organizer_id = session['user_id']

        conn.execute('INSERT INTO conferences (title, description, date, organizer_id) VALUES (?, ?, ?, ?)',
                     (title, description, date, organizer_id))
        conn.commit()
        flash('Conference created successfully.')

    conferences = conn.execute('SELECT * FROM conferences WHERE organizer_id = ?', (session['user_id'],)).fetchall()

    # Add registration count to each conference
    conference_data = []
    for conf in conferences:
        reg_count = conn.execute('SELECT COUNT(*) FROM registrations WHERE conference_id = ?',
                                 (conf['id'],)).fetchone()[0]
        conference_data.append({**dict(conf), 'registrations': reg_count})

    conn.close()
    return render_template('organizer_conferences.html', conferences=conference_data)

# Edit an existing conference
@app.route('/organizer/conference/edit/<int:conf_id>', methods=['GET', 'POST'])
def edit_conference(conf_id):
    if session.get('role') != 'organizer':
        return redirect(url_for('login'))

    conn = get_db_connection()
    conference = conn.execute('SELECT * FROM conferences WHERE id = ? AND organizer_id = ?',
                              (conf_id, session['user_id'])).fetchone()

    if not conference:
        flash("Conference not found or you're not authorized.")
        return redirect(url_for('create_conference'))

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        date = request.form['date']

        conn.execute('UPDATE conferences SET title = ?, description = ?, date = ? WHERE id = ?',
                     (title, description, date, conf_id))
        conn.commit()
        conn.close()
        flash("Conference updated.")
        return redirect(url_for('create_conference'))

    conn.close()
    return render_template('edit_conference.html', conference=conference)

# Delete a conference
@app.route('/organizer/conference/delete/<int:conf_id>')
def delete_conference(conf_id):
    if session.get('role') != 'organizer':
        return redirect(url_for('login'))

    conn = get_db_connection()
    conn.execute('DELETE FROM registrations WHERE conference_id = ?', (conf_id,))
    conn.execute('DELETE FROM conferences WHERE id = ? AND organizer_id = ?',
                 (conf_id, session['user_id']))
    conn.commit()
    conn.close()

    flash("Conference deleted.")
    return redirect(url_for('create_conference'))

# View available conferences for attendees
@app.route('/attendee/conferences')
def view_conferences():
    if session.get('role') != 'attendee':
        return redirect(url_for('login'))

    conn = get_db_connection()
    all_confs = conn.execute('SELECT c.*, u.username AS organizer FROM conferences c JOIN users u ON c.organizer_id = u.id').fetchall()

    registered = conn.execute('SELECT conference_id FROM registrations WHERE user_id = ?', (session['user_id'],)).fetchall()
    registered_ids = {row['conference_id'] for row in registered}
    conn.close()

    return render_template('attendee_conferences.html', conferences=all_confs, registered_ids=registered_ids)

# Register for a conference
@app.route('/attendee/register/<int:conf_id>')
def register_conference(conf_id):
    if session.get('role') != 'attendee':
        return redirect(url_for('login'))

    conn = get_db_connection()
    try:
        conn.execute('INSERT INTO registrations (user_id, conference_id) VALUES (?, ?)',
                     (session['user_id'], conf_id))
        conn.commit()
        flash('Registered successfully!')
    except sqlite3.IntegrityError:
        flash('Already registered for this conference.')
    conn.close()
    return redirect(url_for('view_conferences'))

# Unregister from a conference
@app.route('/attendee/unregister/<int:conf_id>')
def unregister_conference(conf_id):
    if session.get('role') != 'attendee':
        return redirect(url_for('login'))

    conn = get_db_connection()
    conn.execute('DELETE FROM registrations WHERE user_id = ? AND conference_id = ?',
                 (session['user_id'], conf_id))
    conn.commit()
    conn.close()

    flash("Unregistered from conference.")
    return redirect(url_for('view_conferences'))

# Organizer dashboard
@app.route('/dashboard/organizer')
def dashboard_organizer():
    if session.get('role') != 'organizer':
        flash("Unauthorized access.")
        return redirect(url_for('login'))
    return render_template('dashboard_organizer.html', username=session.get('username'))

# Attendee dashboard
@app.route('/dashboard/attendee')
def dashboard_attendee():
    if session.get('role') != 'attendee':
        flash("Unauthorized access.")
        return redirect(url_for('login'))
    return render_template('dashboard_attendee.html', username=session.get('username'))

# Logout
@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out.")
    return redirect(url_for('login'))

# Run the app
if __name__ == '__main__':
    init_db()  # Initialize the DB before starting the app
    app.run(debug=True)
