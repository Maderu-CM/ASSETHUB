from models.user import db, User  

import datetime

class PasswordResetToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False) 
    token = db.Column(db.String(100), nullable=False)
    expiration = db.Column(db.DateTime, nullable=False)

    user = db.relationship('User', backref='reset_tokens')

    def __init__(self, user_id, token, expiration_time=3600):
        self.user_id = user_id
        self.token = token
        self.expiration = datetime.datetime.utcnow() + datetime.timedelta(seconds=expiration_time)
