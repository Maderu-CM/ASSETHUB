from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class AssetRequest(db.Model):
    __tablename__ = 'asset_requests'

    id = db.Column(db.Integer, primary_key=True)
    requester_name = db.Column(db.String(50))
    asset_id = db.Column(db.Integer, db.ForeignKey('assets.id'), nullable=False)  
    reason = db.Column(db.String(200))
    quantity = db.Column(db.Integer)
    urgency = db.Column(db.String(100))
    status = db.Column(db.String(20))
