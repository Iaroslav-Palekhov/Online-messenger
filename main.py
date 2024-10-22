import hashlib
from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///messenger.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'your_secret_key'
db = SQLAlchemy(app)

# Определение моделей
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)  # Поле для пароля
    messages = db.relationship('Message', backref='sender', foreign_keys='Message.user_id', lazy=True)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(200), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

with app.app_context():
    db.create_all()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()  # Хеширование пароля

def check_password(hashed_password, user_password):
    return hashed_password == hashlib.sha256(user_password.encode()).hexdigest()  # Проверка пароля

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Проверка на существование имени пользователя
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return render_template('register.html', error="Username already exists. Please choose a different one.")

        hashed_password = hash_password(password)  # Хеширование пароля
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password(user.password, password):  # Проверка пароля
            session['user_id'] = user.id
            return redirect(url_for('messages'))
    return render_template('login.html')

@app.route('/messages', methods=['GET', 'POST'])
def messages():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    users = User.query.all()  # Получаем всех пользователей

    if request.method == 'POST':
        recipient_username = request.form['recipient']
        content = request.form['content']
        recipient = User.query.filter_by(username=recipient_username).first()
        if recipient:
            new_message = Message(content=content, user_id=user_id, recipient_id=recipient.id)
            db.session.add(new_message)
            db.session.commit()

    # Фильтруем пользователей, чтобы оставить только тех, с кем есть сообщения
    existing_chats = Message.query.filter(
        (Message.user_id == user_id) | (Message.recipient_id == user_id)
    ).distinct().all()

    chat_user_ids = {msg.recipient_id if msg.user_id == user_id else msg.user_id for msg in existing_chats}
    filtered_users = [user for user in users if user.id in chat_user_ids]

    return render_template('messages.html', users=filtered_users)

@app.route('/chat/<int:recipient_id>')
def chat(recipient_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    messages = Message.query.filter(
        ((Message.user_id == user_id) & (Message.recipient_id == recipient_id)) |
        ((Message.user_id == recipient_id) & (Message.recipient_id == user_id))
    ).all()  # Исправлено количество скобок

    recipient = User.query.get(recipient_id)
    return render_template('chat.html', messages=messages, recipient=recipient)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)