from flask_sqlalchemy import SQLAlchemy

db= SQLAlchemy()

class AssetAllocation(db.Model):
    __tablename__ = 'asset_allocations'

    id = db.Column(db.Integer, primary_key=True)
    asset_name = db.Column(db.String, db.ForeignKey('assets.asset_name'), nullable=False)
    username = db.Column(db.String(100))
    description = db.Column(db.String(200))
    allocate_datetime = db.Column(db.DateTime)