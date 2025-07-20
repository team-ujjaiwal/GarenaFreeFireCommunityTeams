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

# Encrypt a protobuf message
def encrypt_message(plaintext):
    try:
        key = b'Yg&tc%DEuh6%Zc^8'
        iv = b'6oyZDr22E3ychjM%'
        cipher = AES.new(key, AES.MODE_CBC, iv)
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

# Fetch tokens from multiple JWT APIs
async def fetch_all_tokens():
    urls = [
        "https://free-fire-india-six.vercel.app/token",
        "https://free-fire-india-five.vercel.app/token",
        "https://free-fire-india-four.vercel.app/token",
        "https://free-fire-india-three.vercel.app/token",
        "https://free-fire-india-two.vercel.app/token"
    ]
    all_tokens = []
    try:
        async with aiohttp.ClientSession() as session:
            tasks = [session.get(url, timeout=10) for url in urls]
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            for response in responses:
                if isinstance(response, Exception):
                    app.logger.error(f"Token fetch error: {response}")
                    continue
                if response.status != 200:
                    app.logger.error(f"Token API failed with status: {response.status}")
                    continue
                data = await response.json()
                tokens = data.get("tokens", [])
                all_tokens.extend(tokens)
        return all_tokens if all_tokens else None
    except Exception as e:
        app.logger.error(f"Error fetching tokens: {e}")
        return None

# Send like request for a token
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
            'ReleaseVersion': "OB49"
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=edata, headers=headers) as response:
                return await response.text() if response.status == 200 else None
    except Exception as e:
        app.logger.error(f"Send request error: {e}")
        return None

# Send requests in batches
async def send_multiple_requests(uid, server_name, url):
    try:
        region = server_name
        protobuf_msg = create_protobuf_message(uid, region)
        if not protobuf_msg:
            return None
        encrypted_uid = encrypt_message(protobuf_msg)
        if not encrypted_uid:
            return None

        tokens = await fetch_all_tokens()
        if not tokens:
            return None

        batch_size = 20
        results = []
        for i in range(0, len(tokens), batch_size):
            batch = tokens[i:i + batch_size]
            tasks = [send_request(encrypted_uid, token, url) for token in batch]
            results.extend(await asyncio.gather(*tasks))
        return results
    except Exception as e:
        app.logger.error(f"Batch request error: {e}")
        return None

# Decode protobuf response
def decode_protobuf(binary):
    try:
        item = like_count_pb2.Info()
        item.ParseFromString(binary)
        return item
    except Exception as e:
        app.logger.error(f"Protobuf decode error: {e}")
        return None

# Request player data
def make_request(encrypted, region, token):
    try:
        url_map = {
            "IND": "https://client.ind.freefiremobile.com/GetPlayerPersonalShow",
            "BR": "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
            "US": "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
            "SAC": "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
            "NA": "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
        }
        url = url_map.get(region, "https://clientbp.ggblueshark.com/GetPlayerPersonalShow")
        edata = bytes.fromhex(encrypted)
        headers = {
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded"
        }
        response = requests.post(url, data=edata, headers=headers, verify=False)
        return decode_protobuf(response.content)
    except Exception as e:
        app.logger.error(f"Make request error: {e}")
        return None

@app.route('/like', methods=['GET'])
def handle_requests():
    uid = request.args.get("uid")
    region = request.args.get("region", "IND").upper()
    key = request.args.get("key")

    if key != "2yearkeysforujjaiwal":
        return jsonify({"error": "Invalid API key"}), 403
    if not uid or not region:
        return jsonify({"error": "Missing uid or region"}), 400

    try:
        token_resp = requests.get("https://free-fire-india-six.vercel.app/token", timeout=10).json()
        token = token_resp.get("tokens", [None])[0]
        if not token:
            raise Exception("No initial token available.")

        encrypted_uid = enc(uid)
        if not encrypted_uid:
            raise Exception("Encryption failed.")

        before = make_request(encrypted_uid, region, token)
        if not before:
            raise Exception("Failed to fetch initial player info.")
        data_before = json.loads(MessageToJson(before))
        before_like = int(data_before.get("AccountInfo", {}).get("Likes", 0))

        like_url = (
            "https://client.ind.freefiremobile.com/LikeProfile"
            if region == "IND"
            else "https://client.us.freefiremobile.com/LikeProfile"
        )

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(send_multiple_requests(uid, region, like_url))

        after = make_request(encrypted_uid, region, token)
        if not after:
            raise Exception("Failed to fetch final player info.")
        data_after = json.loads(MessageToJson(after))
        after_like = int(data_after.get("AccountInfo", {}).get("Likes", 0))

        return jsonify({
            "LikesGivenByAPI": after_like - before_like,
            "LikesbeforeCommand": before_like,
            "LikesafterCommand": after_like,
            "PlayerNickname": data_after.get("AccountInfo", {}).get("PlayerNickname", ""),
            "UID": uid,
            "status": 1 if after_like > before_like else 2
        })

    except Exception as e:
        app.logger.error(f"Final handler error: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)