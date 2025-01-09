from flask import Flask, request, jsonify
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
from azure.cosmos import CosmosClient
import os

app = Flask(__name__)
CORS(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Azure Cosmos DB Configuration
COSMOS_ENDPOINT = os.getenv("COSMOS_ENDPOINT")
COSMOS_KEY = os.getenv("COSMOS_KEY")
DATABASE_NAME = "AimTrainerDB"
CONTAINER_NAME = "Users"

# Cosmos DB Client Setup
client = CosmosClient(COSMOS_ENDPOINT, COSMOS_KEY)
database = client.get_database_client(DATABASE_NAME)
container = database.get_container_client(CONTAINER_NAME)

# JWT Configuration
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')

# User Registration Endpoint
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')

    # Check if user exists
    user_exists = list(container.query_items(
        query="SELECT * FROM c WHERE c.username=@username",
        parameters=[{"name": "@username", "value": data['username']}],
        enable_cross_partition_query=True
    ))

    if user_exists:
        return jsonify({"message": "Username already taken"}), 400

    container.upsert_item({
        "id": data['username'],
        "username": data['username'],
        "password": hashed_password
    })

    return jsonify({"message": "User registered successfully"}), 201

# User Login Endpoint
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user_query = list(container.query_items(
        query="SELECT * FROM c WHERE c.username=@username",
        parameters=[{"name": "@username", "value": data['username']}],
        enable_cross_partition_query=True
    ))

    if not user_query or not bcrypt.check_password_hash(user_query[0]['password'], data['password']):
        return jsonify({"message": "Invalid credentials"}), 401

    token = create_access_token(identity=data['username'])
    return jsonify({"token": token}), 200

# Protected Route Example
@app.route('/dashboard', methods=['GET'])
@jwt_required()
def dashboard():
    current_user = get_jwt_identity()
    return jsonify({"message": f"Welcome {current_user}!"})

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)