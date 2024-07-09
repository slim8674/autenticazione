from flask import Flask, request, render_template, redirect, session, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'chiave_segreta'

def get_db():
    db = sqlite3.connect('database.db')
    db.row_factory = sqlite3.Row
    return db

def init_db():
    db = get_db()
    db.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL)')
    db.close()

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        try:
            db.execute('INSERT INTO users (username, password) VALUES (?, ?)',
                       (username, generate_password_hash(password)))
            db.commit()
            flash('Registrazione avvenuta con successo!', 'success')
            return redirect('/login')
        except sqlite3.IntegrityError:
            flash('Username già esistente', 'error')
        finally:
            db.close()
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        db.close()
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            flash('Login effettuato con successo!', 'success')
            return redirect('/dashboard')
        flash('Username o password non validi', 'error')
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        db = get_db()
        user = db.execute('SELECT username FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        db.close()
        return render_template('dashboard.html', username=user['username'])
    return redirect('/login')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Logout effettuato', 'info')
    return redirect('/')

if __name__ == '__main__':
    init_db()
    app.run(debug=True)