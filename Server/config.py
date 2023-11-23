import os

class CloudinaryConfig:
    CLOUDINARY_CLOUD_NAME = os.getenv('dqdgblwga')
    CLOUDINARY_API_KEY = os.getenv('138726144337926')
    CLOUDINARY_API_SECRET = os.getenv('ucxAh7RmDwLoNsbmJpQARngrp24')

class SQLAlchemyConfig:
    SQLALCHEMY_DATABASE_URI = 'sqlite:///Asset.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False