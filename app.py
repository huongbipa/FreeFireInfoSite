import asyncio
import time
import json
import base64
import random
import httpx

from flask import Flask, request, jsonify
from flask_cors import CORS
from cachetools import TTLCache
from collections import defaultdict
from functools import wraps
from typing import Tuple

from Crypto.Cipher import AES
from google.protobuf import json_format, message
from google.protobuf.message import Message

from proto import FreeFire_pb2, main_pb2, AccountPersonalShow_pb2

# ================= CONFIG =================
MAIN_KEY = base64.b64decode("WWcmdGMlREV1aDYlWmNeOA==")
MAIN_IV  = base64.b64decode("Nm95WkRyMjJFM3ljaGpNJQ==")
RELEASEVERSION = "OB49"

USERAGENT = "Dalvik/2.1.0 (Linux; Android 13)"
SUPPORTED_REGIONS = {
    "IND","BR","US","SAC","NA","SG","RU","ID",
    "TW","VN","TH","ME","PK","CIS","BD","EUROPE"
}

# ================= APP =================
app = Flask(__name__)
CORS(app)

cache = TTLCache(maxsize=300, ttl=300)
cached_tokens = defaultdict(dict)

loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)

http_client = httpx.AsyncClient(timeout=10)

# ================= UTILS =================
def pad(data: bytes) -> bytes:
    pad_len = AES.block_size - len(data) % AES.block_size
    return data + bytes([pad_len] * pad_len)

def aes_encrypt(data: bytes) -> bytes:
    return AES.new(MAIN_KEY, AES.MODE_CBC, MAIN_IV).encrypt(pad(data))

def decode_proto(data: bytes, proto: Message):
    msg = proto()
    msg.ParseFromString(data)
    return msg

async def json_to_proto(data: dict, proto: Message) -> bytes:
    json_format.ParseDict(data, proto)
    return proto.SerializeToString()

# ================= ACCOUNTS =================
def get_account_credentials(region: str) -> str:
    creds = {
        "VN": "uid=4288152181&password=257CAE26A465B6281FEE565DB7A22DB67304B805BF6111EC7DBBFBFBA92049F7",
        "ID": "uid=3692307512&password=4AA06E1DB3F998AB...",
        "SG": "uid=3692265171&password=A2A5E3C252A35B2B...",
    }
    return creds.get(region, creds["VN"])

# ================= TOKEN =================
async def get_access_token(account: str):
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = (
        account +
        "&response_type=token&client_type=2"
        "&client_secret=2ee44819e9b4598845141067b2816218"
        "&client_id=100067"
    )
    r = await http_client.post(url, data=payload)
    j = r.json()
    return j.get("access_token"), j.get("open_id")

async def create_jwt(region: str):
    account = get_account_credentials(region)
    token, open_id = await get_access_token(account)

    body = {
        "open_id": open_id,
        "open_id_type": "4",
        "login_token": token,
        "orign_platform_type": "4"
    }

    payload = aes_encrypt(
        await json_to_proto(body, FreeFire_pb2.LoginReq())
    )

    headers = {
        "User-Agent": USERAGENT,
        "Content-Type": "application/octet-stream",
        "ReleaseVersion": RELEASEVERSION
    }

    r = await http_client.post(
        "https://loginbp.ggblueshark.com/MajorLogin",
        data=payload,
        headers=headers
    )

    msg = json.loads(
        json_format.MessageToJson(
            decode_proto(r.content, FreeFire_pb2.LoginRes)
        )
    )

    cached_tokens[region] = {
        "token": f"Bearer {msg['token']}",
        "server": msg["serverUrl"],
        "expires": time.time() + 25000
    }

async def get_token(region: str):
    t = cached_tokens.get(region)
    if not t or time.time() > t["expires"]:
        await create_jwt(region)
        t = cached_tokens[region]
    return t["token"], t["server"]

# ================= API =================
async def get_player_info(uid: str, region: str):
    payload = aes_encrypt(
        await json_to_proto(
            {"a": uid, "b": "7"},
            main_pb2.GetPlayerPersonalShow()
        )
    )

    token, server = await get_token(region)

    headers = {
        "Authorization": token,
        "User-Agent": USERAGENT,
        "Content-Type": "application/octet-stream",
        "ReleaseVersion": RELEASEVERSION
    }

    r = await http_client.post(
        server + "/GetPlayerPersonalShow",
        data=payload,
        headers=headers
    )

    return json.loads(
        json_format.MessageToJson(
            decode_proto(
                r.content,
                AccountPersonalShow_pb2.AccountPersonalShowInfo
            )
        )
    )

# ================= CACHE =================
def cached(ttl=300):
    def deco(fn):
        @wraps(fn)
        def wrap(*a, **k):
            key = request.full_path
            if key in cache:
                return cache[key]
            res = fn(*a, **k)
            cache[key] = res
            return res
        return wrap
    return deco

# ================= ROUTES =================
@app.route("/player-info")
@cached()
def player_info():
    uid = request.args.get("uid")
    region = request.args.get("region", "").upper()

    if not uid or region not in SUPPORTED_REGIONS:
        return jsonify({"error": "Invalid UID or REGION"}), 400

    try:
        data = loop.run_until_complete(
            get_player_info(uid, region)
        )
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/refresh")
def refresh():
    loop.run_until_complete(
        asyncio.gather(
            *[create_jwt(r) for r in SUPPORTED_REGIONS]
        )
    )
    return jsonify({"status": "refreshed"})

# ================= START =================
if __name__ == "__main__":
    loop.run_until_complete(
        asyncio.gather(
            *[create_jwt(r) for r in SUPPORTED_REGIONS]
        )
    )
    app.run("0.0.0.0", 5000)
