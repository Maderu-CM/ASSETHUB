from flask import Flask, request, jsonify
from flask_cors import CORS
from models.dbconfig import db
from config import SQLAlchemyConfig, CloudinaryConfig
from models.user import User
from models.role import Role
from models.asset import Asset
from models.assetAllocation import AssetAllocation
from models.assetRequest import AssetRequest
from models.passwordResetToken import PasswordResetToken
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import timedelta, datetime
import traceback

def create_app():
    app= Flask(__name__)
    app.secret_key = 'ucxAh7RmDwLoNsbmJpQARngrp24'
    CORS(app)
    app.config['SQLALCHEMY_DATABASE_URI'] = SQLAlchemyConfig.SQLALCHEMY_DATABASE_URI
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = SQLAlchemyConfig.SQLALCHEMY_TRACK_MODIFICATIONS
    db.init_app(app)
    bcrypt = Bcrypt(app)
    jwt_manager = JWTManager(app)

    @app.route('/register', methods=['POST'])
    def register():
        try:
            data = request.get_json()
            username = data.get('username')
            email = data.get('email')
            password = data.get('password')
            role = data.get('role')
            
            existing_user = User.query.filter_by(username=username).first()
            if existing_user:
                return jsonify({'message': 'Username already exists. Please choose another username.'}), 400
            
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            new_user = User(username=username, password=hashed_password, email=email, role_name=role)
            db.session.add(new_user)
            db.session.commit()
            return jsonify({'message': 'User registered successfully'}), 201

        except Exception as e:
            print(f"Error: {str(e)}")
            print(traceback.format_exc())
            return jsonify({'message': 'An error occurred while registering the user'}), 500
        
    @app.route('/login', methods= ['POST'])
    def login():
        data = request.get_json()
        username= data.get('username')
        password= data.get('password')
        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            expiration_time= timedelta(hours=24)
            access_token = create_access_token(identity={'user_id': user.id, 'role': user.role}, expires_delta=expiration_time)
            return jsonify({'message': 'Login successful', 'access_token': access_token, 'role': user.role}), 200
        else:
            return jsonify({'message': 'Invalid username or password'}), 401   

    @app.route('/add_data', methods=['POST'])
    @jwt_required()
    def add_data():
        current_user = get_jwt_identity()
        user_role = current_user.get('role')

        if user_role in ['Admin', 'Procurement Manager']:
            data = request.get_json()

            # Validating fields for Asset Model 
            asset_required_fields = ['asset_name', 'category', 'description', 'image']
            if not all(field in data for field in asset_required_fields):
                missing_fields = ', '.join(set(asset_required_fields) - set(data.keys()))
                return jsonify({'message': f"Missing fields for Asset: {missing_fields}"}), 400

            # Create an asset 
            new_asset = Asset(
                asset_name=data['asset_name'],
                category=data['category'],
                description=data['description'],
                image=data['image']
            )

            # Validating fields for AssetAllocation 
            allocation_required_fields = ['username', 'description', 'allocate_datetime']
            if not all(field in data for field in allocation_required_fields):
                missing_fields = ', '.join(set(allocation_required_fields) - set(data.keys()))
                return jsonify({'message': f"Missing fields for AssetAllocation: {missing_fields}"}), 400

            # Asset allocation
            new_allocation = AssetAllocation(
                asset_name=new_asset.asset_name,  # Assuming you reference asset name in allocation
                username=data['username'],
                description=data['description'],
                allocate_datetime=data['allocate_datetime']
            )

            # Add new entries to the database 
            db.session.add(new_asset)
            db.session.add(new_allocation)
            db.session.commit()

            return jsonify({'message': 'Asset and Allocation added successfully'}), 201
        else:
            return jsonify({'message': 'Unauthorized. Only Admins and Procurement Managers can add assets.'}), 403
        
    @app.route('/update_data/<int:data_id>', methods=['PUT'])
    @jwt_required()
    def update_data(data_id):
        current_user = get_jwt_identity()
        if current_user.get('role') == 'Admin':
            data = request.get_json()

            # Fetch the asset to update from the database
            asset_to_update = Asset.query.get(data_id)

            if asset_to_update:
                # Update fields if they exist in the data
                allowed_fields = ['asset_name', 'category', 'description', 'image']

                for field in allowed_fields:
                    if field in data:
                        setattr(asset_to_update, field, data[field])

                # Commit changes to the database
                db.session.commit()

                return jsonify({'message': 'Asset updated successfully'}), 200
            else:
                return jsonify({'message': 'Asset not found'}), 404
        else:
            return jsonify({'message': 'Unauthorized. Only Admins can update assets.'}), 403
        
    @app.route('/remove_data/<int:data_id>', methods=['DELETE'])
    @jwt_required()
    def remove_data(data_id):
        current_user = get_jwt_identity()
        if current_user.get('role') == 'Admin':
            data_record = Asset.query.get(data_id)
            if data_record:
                # Check if the asset is not allocated to any user
                if data_record.user:
                    return jsonify({'message': 'Asset is allocated to a user and cannot be removed.'}), 400
                
                db.session.delete(data_record)
                db.session.commit()
                return jsonify({'message': 'Asset removed successfully'}), 200
            else:
                return jsonify({'message': 'Asset not found'}), 404
        else:
            return jsonify({'message': 'Unauthorized. Only Admins can remove data.'}), 403
            
    @app.route ('/get_asset/<int:asset_id>', methods= ['GET'])
    @jwt_required()
    def get_asset(asset_id):
        asset=Asset.query.get(asset_id)

        if not asset:
            return jsonify({'message': 'Asset not found'}), 404

        asset_data= {
            'id': asset.id,
            'asset_name': asset.asset_name,
            'description': asset.description,
            'category': asset.category,
            'image' : asset.image,
        }

        return jsonify (asset_data), 200
    

    @app.route('/get_all_assets', methods= ['GET'])
    @jwt_required()
    def get_all_assets():
        assets = Asset.query.all()

        asset_list= []
        for asset in assets:
            asset_list.append({
                'id': asset.id,
            'asset_name': asset.asset_name,
            'description': asset.description,
            'category': asset.category,
            'image' : asset.image,
            })
            return jsonify ({'assets': asset_list}), 200
    

    @app.route('/admin_view_user_requests', methods=['GET'])
    @jwt_required()
    def admin_view_user_requests():
        current_user = get_jwt_identity()
        if current_user.get('role') == 'Admin':
            active_requests = AssetRequest.query.filter_by(status='active').all()
            completed_requests = AssetRequest.query.filter_by(status='completed').all()
            active_requests_list = []
            completed_requests_list = []

            for request in active_requests:
                active_requests_list.append({
                    'id': request.id,
                    'requester_name': request.requester_name,
                    'asset_name': request.asset_name,
                    'reason': request.reason,
                    'quantity': request.quantity,
                    'urgency': request.urgency
                })

            for request in completed_requests:
                completed_requests_list.append({
                    'id': request.id,
                    'requester_name': request.requester_name,
                    'asset_name': request.asset_name,
                    'reason': request.reason,
                    'quantity': request.quantity,
                    'urgency': request.urgency
                })

            return jsonify({
                'active_requests': active_requests_list,
                'completed_requests': completed_requests_list
            }), 200
        else:
            return jsonify({'message': 'Unauthorized. Only Admins can view user requests.'}), 403
        
    @app.route('/admin_view_asset_requests', methods=['GET'])
    @jwt_required()
    def admin_view_asset_requests():
        current_user = get_jwt_identity()
        if current_user.get('role') == 'Admin':
            pending_requests = AssetRequest.query.filter_by(status='pending').all()
            completed_requests = AssetRequest.query.filter_by(status='completed').all()
            pending_requests_list = []
            completed_requests_list = []

            for request in pending_requests:
                pending_requests_list.append({
                    'id': request.id,
                    'requester_name': request.requester_name,
                    'asset_id': request.asset_id,
                    'reason': request.reason,
                    'quantity': request.quantity,
                    'urgency': request.urgency
                })

            for request in completed_requests:
                completed_requests_list.append({
                    'id': request.id,
                    'requester_name': request.requester_name,
                    'asset_id': request.asset_id,
                    'reason': request.reason,
                    'quantity': request.quantity,
                    'urgency': request.urgency
                })

            return jsonify({
                'pending_requests': pending_requests_list,
                'completed_requests': completed_requests_list
            }), 200
        else:
            return jsonify({'message': 'Unauthorized. Only Admins can view asset requests.'}), 403

    @app.route('/classify', methods=['GET'])
    @jwt_required()
    def classify_user():
        current_user = get_jwt_identity()
        user_role = current_user.get("role")

        classification = "Unknown"
        if user_role == "Admin":
            classification = "Admin User"
        elif user_role == "Procurement Manager":
            classification = "Procurement Manager"
        elif user_role == "Normal Employee":
            classification = "Normal Employee"

        return jsonify({"message": "Success", "classification": classification}), 200
    
    @app.route('/approve_request/<int:request_id>', methods=['PUT'])
    @jwt_required()
    def approve_request(request_id):
        current_user = get_jwt_identity()

        if current_user.get('role') != 'Procurement Manager':
            return jsonify({'message': 'Unauthorized. Only Procurement Managers can approve requests.'}), 403

        asset_request = AssetRequest.query.get(request_id)

        if not asset_request:
            return jsonify({'message': 'Asset request not found'}), 404

        asset_request.approved = True
        db.session.commit()

        return jsonify({'message': 'Asset request approved successfully'}), 200 
    
    @app.route('/manager_pending_requests', methods=['GET'])
    @jwt_required()
    def manager_pending_requests():
        current_user = get_jwt_identity()
        if current_user.get('role') != 'Procurement Manager':
            return jsonify({'message': 'Unauthorized. Only Procurement Managers can view pending requests.'}), 403
        
        pending_requests = AssetRequest.query.filter_by(status='pending').all()
        requests_list = []

        for request in pending_requests:
            requests_list.append({
                'id': request.id,
                'requester_name': request.requester_name,
                'asset_id': request.asset_id,
                'reason': request.reason,
                'quantity': request.quantity,
                'urgency': request.urgency
            })

        return jsonify({'pending_requests': requests_list}), 200
    

    @app.route('/manager_completed_requests', methods=['GET'])
    @jwt_required()
    def manager_completed_requests():
        current_user = get_jwt_identity()
        if current_user.get('role') != 'Procurement Manager':
            return jsonify({'message': 'Unauthorized. Only Procurement Managers can view completed requests.'}), 403

        completed_requests = AssetRequest.query.filter_by(status='completed').all()
        requests_list = []

        for request in completed_requests:
            requests_list.append({
                'id': request.id,
                'requester_name': request.requester_name,
                'asset_id': request.asset_id,
                'reason': request.reason,
                'quantity': request.quantity,
                'urgency': request.urgency
            })

        return jsonify({'completed_requests': requests_list}), 200
    
    @app.route('/add_asset', methods=['POST'])
    @jwt_required()
    def add_asset():
        current_user = get_jwt_identity()
        if current_user.get('role') not in ['Admin', 'Procurement Manager']:
            return jsonify({'message': 'Unauthorized. Only Admins and Procurement Managers can add assets.'}), 403

        data = request.get_json()
        asset_name = data.get('asset_name')
        description = data.get('description')
        category = data.get('category')
        image = data.get('image')

        new_asset = Asset(
            asset_name=asset_name,
            description=description,
            category=category,
            image=image,
        )
        db.session.add(new_asset)
        db.session.commit()

        return jsonify({'message': 'Asset added successfully'}), 201
    
    @app.route('/update_asset/<int:asset_id>', methods=['PUT'])
    @jwt_required()
    def update_asset(asset_id):
        current_user = get_jwt_identity()
        if current_user.get('role') not in ['Admin']:
            return jsonify({'message': 'Unauthorized. Only Admins and Procurement Managers can update assets.'}), 403

        asset = Asset.query.get(asset_id)

        if not asset:
            return jsonify({'message': 'Asset not found'}), 404

        data = request.get_json()

        if 'asset_name' in data:
            asset.asset_name = data['asset_name']
        if 'description' in data:
            asset.description = data['description']
        if 'category' in data:
            asset.category = data['category']
        if 'image' in data:
            asset.image = data['image']

        try:
            db.session.commit()
            return jsonify({'message': 'Asset updated successfully'}), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'message': 'Failed to update asset. Please check your data.'}), 500
        

    @app.route('/allocate_asset', methods=['POST'])
    @jwt_required()
    def allocate_asset():
        data = request.get_json()
        asset_name = data.get('asset_name')
        username = data.get('username')
        description = data.get('description')
        allocate_datetime_str = data.get('allocate_datetime')

        allocate_datetime = datetime.fromisoformat(allocate_datetime_str) if allocate_datetime_str else None

        asset_allocation = AssetAllocation(asset_name=asset_name, username=username, description=description, allocate_datetime=allocate_datetime)
        db.session.add(asset_allocation)

        try:
            db.session.commit()
            return jsonify({'message': 'Asset allocated to employee successfully'}), 201
        except Exception as e:
            db.session.rollback()
            return jsonify({'message': 'Failed to allocate asset. Please check your data.'}), 500
            
    @app.route('/request_asset', methods=['POST'])
    @jwt_required()
    def request_asset():
        try:
            current_user = get_jwt_identity()
            print(f"JWT Payload: {current_user}")  

            allowed_roles = ['Normal Employee', 'normalEmployee']  
            if current_user.get('role') not in allowed_roles:
                return jsonify({'message': 'Unauthorized. Only Normal Employees can request assets.'}), 403

            data = request.get_json()
            
            reason = data.get('reason')
            quantity = data.get('quantity')
            urgency = data.get('urgency')

            # Create an asset request
            asset_request = AssetRequest(
                requester_name=current_user.get('username'),  # Assuming the username is used as the requester_name
                reason=reason,
                quantity=quantity,
                urgency=urgency,
                status='Pending'  # Setting an initial status for the request
            )

            db.session.add(asset_request)
            db.session.commit()

            return jsonify({'message': 'Asset request submitted successfully'}), 200

        except Exception as e:
            print(e)  
            return jsonify({'message': 'Internal Server Error'}), 500
        
    @app.route('/user_requests', methods=['GET'])
    @jwt_required()
    def user_requests():
        current_user = get_jwt_identity()
        user_id = current_user.get('user_id')

        # Fetching active, approved, and rejected requests by the current user
        active_requests = AssetRequest.query.filter_by(requester_name=user_id, status='Pending').all()
        approved_requests = AssetRequest.query.filter_by(requester_name=user_id, status='Approved').all()
        rejected_requests = AssetRequest.query.filter_by(requester_name=user_id, status='Rejected').all()

        active_requests_list = []
        completed_requests_list = []

        for request in active_requests:
            active_requests_list.append({
                'id': request.id,
                'reason': request.reason,
                'quantity': request.quantity,
                'urgency': request.urgency,
                'asset_name': request.asset.asset_name  
                
            })

        for request in approved_requests:
            completed_requests_list.append({
            'id': request.id,
            'reason': request.reason,
            'quantity': request.quantity,
            'urgency': request.urgency,
            'asset_name': request.asset.asset_name  
        })

        for request in rejected_requests:
            completed_requests_list.append({
            'id': request.id,
            'reason': request.reason,
            'quantity': request.quantity,
            'urgency': request.urgency,
            'asset_name': request.asset.asset_name  
        })

        return jsonify({'active_requests': active_requests_list, 'completed_requests': completed_requests_list}), 200

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)