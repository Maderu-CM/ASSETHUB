from faker import Faker
from models.dbconfig import db
from models.asset import Asset
from models.assetAllocation import AssetAllocation
from models.assetRequest import AssetRequest
from models.passwordResetToken import PasswordResetToken
from models.user import User
from models.role import Role
from app import app

fake = Faker()

# Push app context before interacting with the database
app.app_context().push()

# Function to create fake roles
def create_fake_roles():
    roles = ['admin', 'procurement manager', 'normal employee']
    for role_name in roles:
        role = Role(name=role_name)
        db.session.add(role)

# Function to create fake users
def create_fake_users(num_records=10):
    roles = Role.query.all()
    users = []
    for _ in range(num_records):
        role = fake.random_element(roles)
        user = User(
            username=fake.user_name(),
            email=fake.email(),
            password=fake.password(),
            role=role
        )
        users.append(user)
    db.session.add_all(users)

# Function to create fake password reset tokens
def create_fake_password_reset_tokens(num_records=5):
    users = User.query.all()
    tokens = []
    for _ in range(num_records):
        user = fake.random_element(users)
        token = PasswordResetToken(
            user=user,
            token=fake.sha1(),
            expiration=fake.future_datetime(end_date='+30d')
        )
        tokens.append(token)
    db.session.add_all(tokens)

# Function to create fake assets
def create_fake_assets(num_records=12):
    assets = []
    for _ in range(num_records):
        asset = Asset(
            asset_name=fake.word(),
            category=fake.word(),
            description=fake.word(),
            image=fake.image_url(),
        )
        assets.append(asset)
    db.session.add_all(assets)

# Function to create fake asset allocations
def create_fake_asset_allocations(num_records=10):
    assets = Asset.query.all()
    users = User.query.all()
    allocations = []
    for _ in range(num_records):
        asset = fake.random_element(assets)
        user = fake.random_element(users)
        allocation = AssetAllocation(
            asset=asset,
            username=user.username,
            description=fake.sentence(),
            allocate_datetime=fake.date_time_this_decade()
        )
        allocations.append(allocation)
    db.session.add_all(allocations)

# Function to create fake asset requests
def create_fake_asset_requests(num_records=15):
    assets = Asset.query.all()
    users = User.query.all()
    requests = []
    for _ in range(num_records):
        asset = fake.random_element(assets)
        user = fake.random_element(users)
        request = AssetRequest(
            requester_name=user.username,
            asset=asset,
            reason=fake.text(),
            quantity=fake.random_int(min=1, max=10),
            urgency=fake.random_element(elements=('High', 'Medium', 'Low')),
            status=fake.random_element(elements=('Pending', 'Approved', 'Rejected')),
        )
        requests.append(request)
    db.session.add_all(requests)



    if __name__ == "__main__":
        db.create_all()
        create_fake_roles()
        create_fake_users()
        create_fake_password_reset_tokens()
        create_fake_assets()
        create_fake_asset_allocations()
        create_fake_asset_requests()
        print("Database seeded successfully!")
