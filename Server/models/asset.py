from flask_sqlalchemy import SQLAlchemy

db= SQLAlchemy()


class Asset(db.Model):
    __tablename__ = 'assets'

    id = db.Column(db.Integer, primary_key=True)
    asset_name = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(100))
    description = db.Column(db.String(100))
    image = db.Column(db.String(100))

    requests = db.relationship('AssetRequest', backref='asset', lazy=True)
    allocation = db.relationship('AssetAllocation', backref='asset', lazy=True)

