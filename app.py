from flask import Flask, request, jsonify
import asyncio
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
import binascii
import aiohttp
import requests
import json
import like_pb2
import like_count_pb2
import uid_generator_pb2
from google.protobuf.message import DecodeError
from functools import wraps

app = Flask(__name__)

# Timeout decorator for async functions
def timeout(seconds):
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            try:
                return await asyncio.wait_for(func(*args, **kwargs), timeout=seconds)
            except asyncio.TimeoutError:
                app.logger.error(f"Function {func.__name__} timed out after {seconds} seconds")
                return None
        return wrapper
    return decorator

# Constants
KEY = b'Yg&tc%DEuh6%Zc^8'
IV = b'6oyZDr22E3ychjM%'
JWT_API_URLS = [
    "https://free-fire-india-six.vercel.app/token",
    "https://free-fire-india-five.vercel.app/token",
    "https://free-fire-india-four.vercel.app/token",
    "https://free-fire-india-tthree.vercel.app/token",
    "https://free-fire-india-two.vercel.app/token"
]
COMMON_HEADERS = {
    'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
    'Connection': "Keep-Alive",
    'Accept-Encoding': "gzip",
    'Content-Type': "application/x-www-form-urlencoded",
    'Expect': "100-continue",
    'X-Unity-Version': "2018.4.11f1",
    'X-GA': "v1 1",
    'ReleaseVersion': "OB49"
}

# Encrypt a protobuf message
def encrypt_message(plaintext):
    try:
        cipher = AES.new(KEY, AES.MODE_CBC, IV)
        padded_message = pad(plaintext, AES.block_size)
        encrypted_message = cipher.encrypt(padded_message)
        return binascii.hexlify(encrypted_message).decode('utf-8')
    except Exception as e:
        app.logger.error(f"Error encrypting message: {e}")
        return None

# Create protobuf messages
def create_protobuf_message(user_id, region):
    try:
        message = like_pb2.like()
        message.uid = int(user_id)
        message.region = region
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"Error creating protobuf message: {e}")
        return None

def create_protobuf(uid):
    try:
        message = uid_generator_pb2.uid_generator()
        message.saturn_ = int(uid)
        message.garena = 1
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"Error creating uid protobuf: {e}")
        return None

def enc(uid):
    protobuf_data = create_protobuf(uid)
    if protobuf_data is None:
        return None
    return encrypt_message(protobuf_data)

# Fetch tokens with timeout
@timeout(10)
async def fetch_all_tokens():
    try:
        async with aiohttp.ClientSession() as session:
            tasks = [session.get(url) for url in JWT_API_URLS]
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            
            all_tokens = []
            for response in responses:
                if isinstance(response, Exception):
                    continue
                if response.status == 200:
                    data = await response.json()
                    all_tokens.extend(data.get("tokens", []))
            
            return all_tokens if all_tokens else None
    except Exception as e:
        app.logger.error(f"Error fetching tokens: {e}")
        return None

# Send a single like request with timeout
@timeout(15)
async def send_request(encrypted_uid, token, url):
    try:
        edata = bytes.fromhex(encrypted_uid)
        headers = {**COMMON_HEADERS, 'Authorization': f"Bearer {token}"}
        
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=edata, headers=headers) as response:
                if response.status != 200:
                    app.logger.error(f"Request failed with status: {response.status}")
                    return None
                return await response.text()
    except Exception as e:
        app.logger.error(f"Exception in send_request: {e}")
        return None

# Get player info with timeout
@timeout(15)
async def get_player_info(encrypted_uid, server_name, token):
    try:
        if server_name == "IND":
            url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
        elif server_name in {"BR", "US", "SAC", "NA"}:
            url = "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
        else:
            url = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"
            
        edata = bytes.fromhex(encrypted_uid)
        headers = {**COMMON_HEADERS, 'Authorization': f"Bearer {token}"}
        
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=edata, headers=headers) as response:
                if response.status != 200:
                    app.logger.error(f"Info request failed with status: {response.status}")
                    return None
                binary = await response.read()
                items = like_count_pb2.Info()
                items.ParseFromString(binary)
                return items
    except Exception as e:
        app.logger.error(f"Error in get_player_info: {e}")
        return None

@app.route('/like', methods=['GET'])
async def handle_requests():
    uid = request.args.get("uid")
    server_name = request.args.get("region", "").upper()
    key = request.args.get("key")

    if not uid or not server_name or not key:
        return jsonify({"error": "UID, region, and key are required"}), 400

    if key != "1yearkeysforujjaiwal":
        return jsonify({"error": "Invalid API key"}), 403

    try:
        # Get initial token and encrypted UID
        encrypted_uid = enc(uid)
        if not encrypted_uid:
            return jsonify({"error": "Encryption failed"}), 500

        tokens = await fetch_all_tokens()
        if not tokens:
            return jsonify({"error": "Failed to fetch tokens"}), 500

        # Get initial player info
        before_info = await get_player_info(encrypted_uid, server_name, tokens[0])
        if not before_info:
            return jsonify({"error": "Failed to get initial player info"}), 500
            
        before_json = json.loads(MessageToJson(before_info))
        before_like = int(before_json.get('AccountInfo', {}).get('Likes', 0))
        player_name = str(before_json.get('AccountInfo', {}).get('PlayerNickname', ''))
        player_uid = int(before_json.get('AccountInfo', {}).get('UID', 0))

        # Determine like endpoint
        if server_name == "IND":
            like_url = "https://client.ind.freefiremobile.com/LikeProfile"
        elif server_name in {"BR", "US", "SAC", "NA"}:
            like_url = "https://client.us.freefiremobile.com/LikeProfile"
        else:
            like_url = "https://clientbp.ggblueshark.com/LikeProfile"

        # Create protobuf message for likes
        protobuf_message = create_protobuf_message(uid, server_name)
        if not protobuf_message:
            return jsonify({"error": "Failed to create protobuf message"}), 500

        encrypted_message = encrypt_message(protobuf_message)
        if not encrypted_message:
            return jsonify({"error": "Failed to encrypt message"}), 500

        # Send like requests in parallel with timeout
        tasks = [send_request(encrypted_message, token, like_url) for token in tokens]
        await asyncio.gather(*tasks, return_exceptions=True)

        # Get updated player info
        after_info = await get_player_info(encrypted_uid, server_name, tokens[0])
        if not after_info:
            return jsonify({
                "LikesGivenByAPI": "Unknown",
                "LikesbeforeCommand": before_like,
                "PlayerNickname": player_name,
                "UID": player_uid,
                "status": 2,
                "warning": "Could not verify likes after sending"
            }), 200

        after_json = json.loads(MessageToJson(after_info))
        after_like = int(after_json.get('AccountInfo', {}).get('Likes', 0))
        like_given = after_like - before_like
        status = 1 if like_given != 0 else 2

        return jsonify({
            "LikesGivenByAPI": like_given,
            "LikesbeforeCommand": before_like,
            "LikesafterCommand": after_like,
            "PlayerNickname": player_name,
            "UID": player_uid,
            "status": status
        })

    except Exception as e:
        app.logger.error(f"Error processing request: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)