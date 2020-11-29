from datetime import datetime
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from bugtracker import db, login_manager, app
from flask_login import UserMixin


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
    

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    image_file = db.Column(db.String(20), nullable=False, default='default.jpg')
    password = db.Column(db.String(60), nullable=False)
    tickets = db.relationship('Ticket', backref='author', lazy=True)
    access = db.Column(db.String, default="user")

    def is_admin():
        return self.access == "admin"

    def get_reset_token(self, expires_sec=1800):
        s = Serializer(app.config['SECRET_KEY'], expires_sec)
        return s.dumps({'user_id': self.id}).decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return User.query.get(user_id)

    def __repr__(self):
        return f"User('{self.name}', '{self.email}', '{self.image_file}', '{self.access}')"


class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    date_finished = db.Column(db.DateTime)
    content = db.Column(db.Text, nullable=False)
    state = db.Column(db.Text, nullable=False, default="pending") #pending, working on it, fixed, rejected
    severity = db.Column(db.Text, nullable=False) #minor, functional, critical
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"Ticket('{self.title}', '{self.date_posted}')"
