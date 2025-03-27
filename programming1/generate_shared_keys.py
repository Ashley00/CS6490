import secrets
import json

KEY_FILE = "keys.json"

def generate_keys():
    keys = {
        "K_A_KDC": secrets.token_bytes(24).hex(), # 3DES key between Alice and KDC
        "K_B_KDC": secrets.token_bytes(24).hex() # 3DES key between Bob and KDC
    }
    with open(KEY_FILE, "w") as f:
        json.dump(keys, f)

# Run once to generate keys if file doesn't exist
try:
    with open(KEY_FILE, "r") as f:
        keys = json.load(f)
        K_A_KDC = bytes.fromhex(keys["K_A_KDC"])
        K_B_KDC = bytes.fromhex(keys["K_B_KDC"])
except FileNotFoundError:
    generate_keys()
    with open(KEY_FILE, "r") as f:
        keys = json.load(f)
        K_A_KDC = bytes.fromhex(keys["K_A_KDC"])
        K_B_KDC = bytes.fromhex(keys["K_B_KDC"])