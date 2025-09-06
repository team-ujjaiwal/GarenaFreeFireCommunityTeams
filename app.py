from flask import Flask, request, jsonify
import asyncio
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
import binascii
import aiohttp
import requests
import json
import CSLikeProfile_pb2 as like_pb2
import CSLikeProfile_count_pb2 as like_count_pb2
import uid_generator_pb2
from google.protobuf.message import DecodeError
from pymongo import MongoClient, ReturnDocument
from datetime import datetime, timedelta
import uuid
import secrets
import string
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
import atexit
import logging
from functools import wraps

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# MongoDB configuration - Update with your connection string
MONGODB_URI = "mongodb+srv://dk5801690:PWCzVm5tOCixMpAD@cluster0.yxu5vet.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
client = MongoClient(MONGODB_URI)
db = client.freefire_api
api_keys_collection = db.api_keys
request_logs_collection = db.request_logs

# Initialize scheduler for daily reset
scheduler = BackgroundScheduler(daemon=True)
scheduler.start()
atexit.register(lambda: scheduler.shutdown())

def reset_daily_requests():
    """Reset remaining requests for all active keys at midnight UTC"""
    try:
        now = datetime.utcnow()
        result = api_keys_collection.update_many(
            {
                "is_active": True,
                "expires_at": {"$gt": now}
            },
            {
                "$set": {
                    "remaining_requests": "$total_requests",
                    "last_reset": now
                }
            }
        )
        logger.info(f"Reset {result.modified_count} keys at {now}")
    except Exception as e:
        logger.error(f"Error in reset_daily_requests: {e}")

# Schedule daily reset at midnight UTC
scheduler.add_job(
    reset_daily_requests,
    trigger=CronTrigger(hour=0, minute=0, second=0, timezone='UTC')
)

def require_api_key(f):
    """Decorator to require API key authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key') or request.args.get('key')
        if not api_key:
            return jsonify({"error": "API key is required"}), 401
        
        key_data = authenticate_key(api_key)
        if not key_data:
            return jsonify({"error": "Invalid or expired API key"}), 403
        
        # Check remaining requests
        if key_data.get('remaining_requests', 0) <= 0:
            next_reset = (datetime.utcnow() + timedelta(days=1)).replace(
                hour=0, minute=0, second=0, microsecond=0
            )
            return jsonify({
                "error": "No remaining requests available",
                "next_reset": next_reset.isoformat()
            }), 429
        
        # Add key data to request context for use in the route
        request.key_data = key_data
        return f(*args, **kwargs)
    return decorated_function

def load_tokens(server_name):
    try:
        if server_name == "IND":
            with open("token_ind.json", "r") as f:
                tokens = json.load(f)
        elif server_name in {"BR", "US", "SAC", "NA"}:
            with open("token_br.json", "r") as f:
                tokens = json.load(f)
        else:
            with open("token_bd.json", "r") as f:
                tokens = json.load(f)
        return tokens
    except Exception as e:
        logger.error(f"Error loading tokens for server {server_name}: {e}")
        return None

def encrypt_message(plaintext):
    try:
        key = b'Yg&tc%DEuh6%Zc^8'
        iv = b'6oyZDr22E3ychjM%'
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_message = pad(plaintext, AES.block_size)
        encrypted_message = cipher.encrypt(padded_message)
        return binascii.hexlify(encrypted_message).decode('utf-8')
    except Exception as e:
        logger.error(f"Error encrypting message: {e}")
        return None

def create_protobuf_message(user_id, region):
    try:
        message = like_pb2.like()
        message.uid = int(user_id)
        message.region = region
        return message.SerializeToString()
    except Exception as e:
        logger.error(f"Error creating protobuf message: {e}")
        return None

async def send_request(encrypted_uid, token, url):
    try:
        edata = bytes.fromhex(encrypted_uid)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB50"
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=edata, headers=headers) as response:
                if response.status != 200:
                    logger.error(f"Request failed with status code: {response.status}")
                    return response.status
                return await response.text()
    except Exception as e:
        logger.error(f"Exception in send_request: {e}")
        return None

async def send_multiple_requests(uid, server_name, url):
    try:
        region = server_name
        protobuf_message = create_protobuf_message(uid, region)
        if protobuf_message is None:
            logger.error("Failed to create protobuf message.")
            return None
        encrypted_uid = encrypt_message(protobuf_message)
        if encrypted_uid is None:
            logger.error("Encryption failed.")
            return None
        tasks = []
        tokens = load_tokens(server_name)
        if tokens is None:
            logger.error("Failed to load tokens.")
            return None
        for i in range(100):
            token = tokens[i % len(tokens)]["token"]
            tasks.append(send_request(encrypted_uid, token, url))
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return results
    except Exception as e:
        logger.error(f"Exception in send_multiple_requests: {e}")
        return None

def create_protobuf(uid):
    try:
        message = uid_generator_pb2.uid_generator()
        message.ujjaiwal_ = int(uid)
        message.garena = 1
        return message.SerializeToString()
    except Exception as e:
        logger.error(f"Error creating uid protobuf: {e}")
        return None

def enc(uid):
    protobuf_data = create_protobuf(uid)
    if protobuf_data is None:
        return None
    encrypted_uid = encrypt_message(protobuf_data)
    return encrypted_uid

def make_request(encrypt, server_name, token):
    try:
        if server_name == "IND":
            url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
        elif server_name in {"BR", "US", "SAC", "NA"}:
            url = "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
        else:
            url = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"
        edata = bytes.fromhex(encrypt)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB50"
        }
        response = requests.post(url, data=edata, headers=headers, verify=False, timeout=30)
        hex_data = response.content.hex()
        binary = bytes.fromhex(hex_data)
        decode = decode_protobuf(binary)
        if decode is None:
            logger.error("Protobuf decoding returned None.")
        return decode
    except Exception as e:
        logger.error(f"Error in make_request: {e}")
        return None

def decode_protobuf(binary):
    try:
        items = like_count_pb2.Info()
        items.ParseFromString(binary)
        return items
    except DecodeError as e:
        logger.error(f"Error decoding Protobuf data: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error during protobuf decoding: {e}")
        return None

def authenticate_key(api_key):
    """Check if API key exists and is valid"""
    try:
        key_data = api_keys_collection.find_one({"key": api_key})
        if not key_data:
            return None
        
        # Check if key is active
        if not key_data.get('is_active', True):
            return None
        
        # Check expiration
        now = datetime.utcnow()
        if 'expires_at' in key_data and now > key_data['expires_at']:
            # Mark as inactive if expired
            api_keys_collection.update_one(
                {"key": api_key},
                {"$set": {"is_active": False}}
            )
            return None
        
        # Check if we need to reset remaining requests (new day)
        last_reset = key_data.get('last_reset')
        if last_reset and last_reset.date() < now.date():
            # Reset daily requests
            api_keys_collection.update_one(
                {"key": api_key},
                {"$set": {
                    "remaining_requests": key_data['total_requests'],
                    "last_reset": now
                }}
            )
            key_data['remaining_requests'] = key_data['total_requests']
        
        return key_data
    except Exception as e:
        logger.error(f"Error in authenticate_key: {e}")
        return None

def update_key_usage(api_key, decrement=1):
    """Decrement remaining requests count for a key"""
    try:
        result = api_keys_collection.find_one_and_update(
            {"key": api_key, "remaining_requests": {"$gte": decrement}},
            {
                "$inc": {"remaining_requests": -decrement},
                "$set": {"last_used": datetime.utcnow()}
            },
            return_document=ReturnDocument.AFTER
        )
        return result is not None
    except Exception as e:
        logger.error(f"Error updating key usage: {e}")
        return False

def log_request(api_key, endpoint, status, details):
    """Log API request to MongoDB"""
    try:
        log_entry = {
            "api_key": api_key,
            "endpoint": endpoint,
            "timestamp": datetime.utcnow(),
            "status": status,
            "details": details,
            "ip_address": request.remote_addr
        }
        request_logs_collection.insert_one(log_entry)
    except Exception as e:
        logger.error(f"Error logging request: {e}")

@app.route('/api/key/create', methods=['POST'])
def create_key():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Request body is required"}), 400
        
        # Generate a random key if not provided
        custom_key = data.get('custom_key')
        if custom_key:
            # Check if custom key already exists
            if api_keys_collection.find_one({"key": custom_key}):
                return jsonify({"error": "Custom key already exists"}), 400
            api_key = custom_key
        else:
            # Generate a secure random key
            alphabet = string.ascii_letters + string.digits
            api_key = ''.join(secrets.choice(alphabet) for _ in range(32))
        
        # Set key properties
        total_requests = int(data.get('total_requests', 1000))
        expiry_days = int(data.get('expiry_days', 30))
        notes = data.get('notes', '')
        
        expires_at = datetime.utcnow() + timedelta(days=expiry_days)
        
        # Create key document
        key_doc = {
            "key": api_key,
            "created_at": datetime.utcnow(),
            "expires_at": expires_at,
            "total_requests": total_requests,
            "remaining_requests": total_requests,
            "notes": notes,
            "is_active": True,
            "last_reset": datetime.utcnow()
        }
        
        # Insert into MongoDB
        api_keys_collection.insert_one(key_doc)
        
        # Return success response
        return jsonify({
            "message": "API key created successfully",
            "key": api_key,
            "expires_at": expires_at.isoformat(),
            "total_requests": total_requests,
            "notes": notes
        }), 201
        
    except Exception as e:
        logger.error(f"Error creating API key: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/api/key/info', methods=['GET'])
@require_api_key
def get_key_info():
    """Get information about the current API key"""
    try:
        key_data = request.key_data
        
        # Remove MongoDB ID and format dates
        key_data.pop('_id', None)
        for field in ['created_at', 'expires_at', 'last_reset', 'last_used']:
            if field in key_data and isinstance(key_data[field], datetime):
                key_data[field] = key_data[field].isoformat()
        
        return jsonify(key_data), 200
    except Exception as e:
        logger.error(f"Error getting key info: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/api/key/delete', methods=['DELETE'])
@require_api_key
def delete_key():
    """Delete (deactivate) the current API key"""
    try:
        api_key = request.headers.get('X-API-Key') or request.args.get('key')
        
        # Mark the key as inactive instead of deleting it
        result = api_keys_collection.update_one(
            {"key": api_key},
            {"$set": {"is_active": False}}
        )
        
        if result.modified_count == 1:
            log_request(api_key, '/api/key/delete', 'success', 'Key deactivated')
            return jsonify({"message": "API key deactivated successfully"}), 200
        else:
            return jsonify({"error": "Failed to deactivate API key"}), 400
    except Exception as e:
        logger.error(f"Error deleting API key: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/api/keys', methods=['GET'])
def list_keys():
    """List all API keys (admin only)"""
    try:
        # This should be protected with admin authentication in production
        keys = list(api_keys_collection.find({}, {'_id': 0}))
        
        # Format datetime fields
        for key in keys:
            for field in ['created_at', 'expires_at', 'last_reset', 'last_used']:
                if field in key and isinstance(key[field], datetime):
                    key[field] = key[field].isoformat()
        
        return jsonify({"keys": keys}), 200
    except Exception as e:
        logger.error(f"Error listing keys: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/like', methods=['GET'])
@require_api_key
def handle_requests():
    """Main endpoint to send likes to a FreeFire profile"""
    api_key = request.headers.get('X-API-Key') or request.args.get('key')
    uid = request.args.get("uid")
    server_name = request.args.get("server_name", "").upper()
    
    if not uid or not server_name:
        return jsonify({"error": "UID and server_name are required"}), 400

    try:
        # Log the request
        log_request(api_key, '/like', 'processing', {
            'uid': uid,
            'server_name': server_name
        })
        
        # Load tokens for the specified server
        tokens = load_tokens(server_name)
        if tokens is None:
            error_msg = "Failed to load tokens for the specified server"
            log_request(api_key, '/like', 'error', error_msg)
            return jsonify({"error": error_msg}), 500
        
        # Encrypt UID
        encrypted_uid = enc(uid)
        if encrypted_uid is None:
            error_msg = "Encryption of UID failed"
            log_request(api_key, '/like', 'error', error_msg)
            return jsonify({"error": error_msg}), 500
        
        # Get initial like count
        token = tokens[0]['token']
        before = make_request(encrypted_uid, server_name, token)
        if before is None:
            error_msg = "Failed to retrieve initial player info"
            log_request(api_key, '/like', 'error', error_msg)
            return jsonify({"error": error_msg}), 500
        
        try:
            jsone = MessageToJson(before)
            data_before = json.loads(jsone)
            before_like = data_before.get('AccountInfo', {}).get('Likes', 0)
            before_like = int(before_like) if before_like else 0
        except Exception as e:
            error_msg = f"Error processing initial data: {str(e)}"
            log_request(api_key, '/like', 'error', error_msg)
            return jsonify({"error": error_msg}), 500
        
        # Determine the correct URL for likes
        if server_name == "IND":
            url = "https://client.ind.freefiremobile.com/LikeProfile"
        elif server_name in {"BR", "US", "SAC", "NA"}:
            url = "https://client.us.freefiremobile.com/LikeProfile"
        else:
            url = "https://clientbp.ggblueshark.com/LikeProfile"

        # Send like requests asynchronously
        results = asyncio.run(send_multiple_requests(uid, server_name, url))
        if results is None:
            error_msg = "Failed to send like requests"
            log_request(api_key, '/like', 'error', error_msg)
            return jsonify({"error": error_msg}), 500
        
        # Get updated like count
        after = make_request(encrypted_uid, server_name, token)
        if after is None:
            error_msg = "Failed to retrieve player info after like requests"
            log_request(api_key, '/like', 'error', error_msg)
            return jsonify({"error": error_msg}), 500
        
        try:
            jsone_after = MessageToJson(after)
            data_after = json.loads(jsone_after)
            after_like = data_after.get('AccountInfo', {}).get('Likes', 0)
            after_like = int(after_like) if after_like else 0
            player_uid = data_after.get('AccountInfo', {}).get('UID', 0)
            player_uid = int(player_uid) if player_uid else 0
            player_name = data_after.get('AccountInfo', {}).get('PlayerNickname', '')
        except Exception as e:
            error_msg = f"Error processing updated data: {str(e)}"
            log_request(api_key, '/like', 'error', error_msg)
            return jsonify({"error": error_msg}), 500
        
        # Calculate likes given and update key usage
        like_given = after_like - before_like
        status = 1 if like_given > 0 else 2
        
        # Only decrement key usage if likes were successfully given
        if like_given > 0:
            if not update_key_usage(api_key, 1):
                error_msg = "Failed to update key usage"
                log_request(api_key, '/like', 'error', error_msg)
                return jsonify({"error": error_msg}), 500
        
        # Get updated key info
        updated_key_data = authenticate_key(api_key)
        if not updated_key_data:
            error_msg = "Failed to retrieve updated key info"
            log_request(api_key, '/like', 'error', error_msg)
            return jsonify({"error": error_msg}), 500
        
        # Prepare response
        response = {
            "response": {
                "KeyExpiresAt": updated_key_data['expires_at'].isoformat(),
                "KeyRemainingRequests": f"{updated_key_data['remaining_requests']}/{updated_key_data['total_requests']}",
                "LikesGivenByAPI": like_given,
                "LikesafterCommand": after_like,
                "LikesbeforeCommand": before_like,
                "PlayerNickname": player_name,
                "UID": player_uid
            },
            "status": status
        }
        
        # Log successful request
        log_request(api_key, '/like', 'success', {
            'likes_given': like_given,
            'uid': uid,
            'player_name': player_name
        })
        
        return jsonify(response)
        
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        logger.error(error_msg)
        log_request(api_key, '/like', 'error', error_msg)
        return jsonify({"error": "Internal server error"}), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    try:
        # Check MongoDB connection
        api_keys_collection.find_one()
        return jsonify({
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "database": "connected"
        }), 200
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return jsonify({
            "status": "unhealthy",
            "timestamp": datetime.utcnow().isoformat(),
            "database": "disconnected",
            "error": str(e)
        }), 500

if __name__ == '__main__':
    # Create indexes for better performance
    try:
        api_keys_collection.create_index("key", unique=True)
        api_keys_collection.create_index("expires_at")
        api_keys_collection.create_index("is_active")
        request_logs_collection.create_index("timestamp")
        request_logs_collection.create_index("api_key")
    except Exception as e:
        logger.error(f"Error creating indexes: {e}")
    
    app.run(debug=True, host='0.0.0.0', port=5000)