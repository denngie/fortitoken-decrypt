"""Decrypt FortiToken Mobile values to generate your own otpauth string"""

import hashlib
import base64
from Crypto.Cipher import AES  # pip install pycryptodome

# Pull out the second value separated by | from sqlite database located at
# /data/data/com.fortinet.android.ftm/databases/FortiToken.db
# SELECT name, seed, otp_period, digits FROM Account WHERE type="totp"
SEED = "MNmAN7drtlNJxjFqo5bgSN/DZcdWVK9Qv1YyUP3OjuJkDXgV06siQYlQfO0678Lg"

# Pull out the value from UUID key in XML located at
# From /data/data/com.fortinet.android.ftm/shared_prefs/FortiToken_SharedPrefs_NAME.xml
UUID = "N7gAr30eX72sR2owbVR4WrFiw4e3ignGBO6IcgA4qJjvBYjZvIxZXIMTHOix8QDt"

# Pull out the value from SerialNumberPreAndroid9 key In the same XML file
SERIAL = "TOKENSERIALunknown"

# Pull out the value from package com.fortinet.android.ftm in XML located at
# /data/system/users/0/settings_ssaid.xml
DEVICE_ID = "eefd7d4837294e94"


def unpad(s: str) -> str:
    """Unpad the string from byte encoded characters"""
    return s[0 : -ord(s[-1])]


def decrypt(cipher: str, key: str) -> str:
    """Decrypt AES/CBC/PKCS5 cipher with the given key"""
    sha256 = hashlib.sha256()
    sha256.update(bytes(key, "utf-8"))
    digest = sha256.digest()
    iv = bytes([0] * 16)
    aes = AES.new(digest, AES.MODE_CBC, iv)
    decrypted = aes.decrypt(base64.b64decode(cipher))
    return unpad(str(decrypted, "utf-8"))


# Concatenate DEVICE_ID and SERIAL(excluding first 11 characters) to get the decryption key
UUID_KEY = DEVICE_ID + SERIAL[11:]
print(f"UUID KEY: {UUID_KEY}")

# Decrypt UUID using the UUID_KEY
decoded_uuid = decrypt(UUID, UUID_KEY)
print(f"UUID: {decoded_uuid}")

# Decrypt TOTP seed using the decrypted UUID
seed_decryption_key = UUID_KEY + decoded_uuid
print(f"SEED KEY: {seed_decryption_key}")
decrypted_seed = decrypt(SEED, seed_decryption_key)

# Convert seed from hexadecimal to string
totp_secret = bytes.fromhex(decrypted_seed)
TOTP_SECRET_BASE32_ENCODED = str(base64.b32encode(totp_secret), "utf-8")
print(f"TOTP SECRET: {TOTP_SECRET_BASE32_ENCODED}")
