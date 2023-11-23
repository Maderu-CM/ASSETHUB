from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import cloudinary
from config import CloudinaryConfig, SQLAlchemyConfig
from cloudinary.uploader import upload

# Application initialization
app = Flask(__name__)

# Set up configurations
app.config['SQLALCHEMY_DATABASE_URI'] = SQLAlchemyConfig.SQLALCHEMY_DATABASE_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = SQLAlchemyConfig.SQLALCHEMY_TRACK_MODIFICATIONS

# Initialize the database with the app instance
db = SQLAlchemy(app)

# Import your models here (ensure this is placed after creating db)
from models.role import Role
from models.user import User
from models.asset import Asset
from models.assetAllocation import AssetAllocation
from models.assetRequest import AssetRequest
from models.passwordResetToken import PasswordResetToken

# Configure Cloudinary
cloudinary.config(
    cloud_name=CloudinaryConfig.CLOUDINARY_CLOUD_NAME,
    api_key=CloudinaryConfig.CLOUDINARY_API_KEY,
    api_secret=CloudinaryConfig.CLOUDINARY_API_SECRET,
)

# Initialize Flask-Migrate with the db instance and app
migrate = Migrate(app, db)

# Define the upload route
@app.route("/upload", methods=['POST'])
def upload_file():
    if request.method == 'POST':
        file_to_upload = request.files['file']
        if file_to_upload:
            upload_result = upload(file_to_upload)
            return jsonify(upload_result)

if __name__ == "__main__":
    app.run(debug=True)
