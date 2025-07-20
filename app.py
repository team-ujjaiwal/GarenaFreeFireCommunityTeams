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

app = Flask(__name__)

# AES encryption
def encrypt_message(plaintext):
    try:
        key = b'Yg&tc%DEuh6%Zc^8'
        iv = b'6oyZDr22E3ychjM%'
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded = pad(plaintext, AES.block_size)
        encrypted = cipher.encrypt(padded)
        return binascii.hexlify(encrypted).decode('utf-8')
    except Exception as e:
        app.logger.error(f"Encryption error: {e}")
        return None

# Protobuf creation
def create_protobuf_message(uid, region):
    try:
        msg = like_pb2.like()
        msg.uid = int(uid)
        msg.region = region
        return msg.SerializeToString()
    except Exception as e:
        app.logger.error(f"Protobuf creation error: {e}")
        return None

def create_uid_protobuf(uid):
    try:
        msg = uid_generator_pb2.uid_generator()
        msg.saturn_ = int(uid)
        msg.garena = 1
        return msg.SerializeToString()
    except Exception as e:
        app.logger.error(f"UID protobuf error: {e}")
        return None

def enc(uid):
    data = create_uid_protobuf(uid)
    return encrypt_message(data) if data else None

# Fetch tokens from all 5 JWT APIs
async def fetch_all_tokens():
    urls = [
        "https://free-fire-india-six.vercel.app/token",
        "https://free-fire-india-five.vercel.app/token",
        "https://free-fire-india-four.vercel.app/token",
        "https://free-fire-india-three.vercel.app/token",
        "https://free-fire-india-two.vercel.app/token"
    ]
    tokens = []

    async with aiohttp.ClientSession() as session:
        tasks = [session.get(url, timeout=10) for url in urls]
        responses = await asyncio.gather(*tasks, return_exceptions=True)

        for response in responses:
            if isinstance(response, Exception):
                app.logger.error(f"Token fetch error: {response}")
                continue
            if response.status != 200:
                app.logger.error(f"Token API error: {response.status}")
                continue
            try:
                data = await response.json()
                tokens.extend(data.get("tokens", []))
            except Exception as e:
                app.logger.error(f"JSON parse error: {e}")
                continue

    return tokens if tokens else None

# Send one like request
async def send_like(encrypted_uid, token, url, session):
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
            'ReleaseVersion': "OB49"
        }
        async with session.post(url, data=edata, headers=headers) as response:
            return await response.text() if response.status == 200 else None
    except Exception as e:
        app.logger.error(f"Like request error: {e}")
        return None

# Run all likes concurrently
async def send_multiple_requests(uid, server_name, url):
    encrypted_uid = encrypt_message(create_protobuf_message(uid, server_name))
    if not encrypted_uid:
        return None

    tokens = await fetch_all_tokens()
    if not tokens:
        return None

    async with aiohttp.ClientSession() as session:
        tasks = [send_like(encrypted_uid, token, url, session) for token in tokens]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return results

# Decode protobuf
def decode_protobuf(binary):
    try:
        info = like_count_pb2.Info()
        info.ParseFromString(binary)
        return info
    except Exception as e:
        app.logger.error(f"Protobuf decode error: {e}")
        return None

# Get player info
def get_player_info(encrypt, region, token):
    try:
        urls = {
            "IND": "https://client.ind.freefiremobile.com/GetPlayerPersonalShow",
            "BR": "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
            "US": "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
            "SAC": "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
            "NA": "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
        }
        url = urls.get(region, "https://clientbp.ggblueshark.com/GetPlayerPersonalShow")
        headers = {
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded"
        }
        data = bytes.fromhex(encrypt)
        response = requests.post(url, data=data, headers=headers, verify=False)
        return decode_protobuf(response.content)
    except Exception as e:
        app.logger.error(f"Player info fetch error: {e}")
        return None

# Main route
@app.route('/like', methods=['GET'])
def handle_requests():
    uid = request.args.get("uid")
    region = request.args.get("region", "").upper()
    key = request.args.get("key")

    if key != "2yearkeysforujjaiwal":
        return jsonify({"error": "Invalid API key"}), 403
    if not uid or not region:
        return jsonify({"error": "Missing UID or region"}), 400

    try:
        token_data = requests.get("https://free-fire-india-six.vercel.app/token").json()
        token = token_data.get("tokens", [None])[0]
        if not token:
            raise Exception("No token available for player info.")

        encrypted = enc(uid)
        if not encrypted:
            raise Exception("Encryption failed.")

        before_info = get_player_info(encrypted, region, token)
        before_likes = int(json.loads(MessageToJson(before_info)).get("AccountInfo", {}).get("Likes", 0))

        # Set like URL
        if region == "IND":
            like_url = "https://client.ind.freefiremobile.com/LikeProfile"
        elif region in {"BR", "US", "SAC", "NA"}:
            like_url = "https://client.us.freefiremobile.com/LikeProfile"
        else:
            like_url = "https://clientbp.ggblueshark.com/LikeProfile"

        # Send likes
        asyncio.run(send_multiple_requests(uid, region, like_url))

        after_info = get_player_info(encrypted, region, token)
        after_data = json.loads(MessageToJson(after_info))
        after_likes = int(after_data.get("AccountInfo", {}).get("Likes", 0))

        return jsonify({
            "LikesGivenByAPI": after_likes - before_likes,
            "LikesbeforeCommand": before_likes,
            "LikesafterCommand": after_likes,
            "PlayerNickname": after_data.get("AccountInfo", {}).get("PlayerNickname", ""),
            "UID": uid,
            "status": 1 if after_likes > before_likes else 2
        })

    except Exception as e:
        app.logger.error(f"Handler error: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)