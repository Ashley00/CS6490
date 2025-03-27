import socket
import json
import secrets
from util import encrypt_3des, decrypt_3des
from generate_shared_keys import K_A_KDC, K_B_KDC

# Trudy reuses Alice's message
print("Trudy: Performing Reflection Attack")

# Step 1: Read stolen data from file
try:
    with open("stolen_data.json", "r") as f:
        stolen_data = json.load(f)
        fake_ticket = stolen_data["ticket"]
        fake_nonce = stolen_data["K_AB{N2}"]
except FileNotFoundError:
    print("Trudy ERROR: Stolen data file not found!")
    raise FileNotFoundError("Trudy: Stolen data file not found")

print("Trudy: Using stolen ticket and nonce.")

# Step 2: Extract K_AB from ticket
ticket_decrypted = decrypt_3des(K_B_KDC, fake_ticket, 'ECB')
ticket_data = json.loads(ticket_decrypted)

K_AB = bytes.fromhex(ticket_data['K_AB']) 
N2 = secrets.token_bytes(8).hex()

# Step 2: Connect to Bob and replay Alice's message
bob_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
bob_conn.connect(('localhost', 3000))
send_msg = json.dumps({"ticket": fake_ticket, "K_AB{N2}": fake_nonce}).encode()
bob_conn.send(send_msg)
print("Trudy: Send to Bob: ", send_msg.hex())

# Step 3: Trudy receive from bob
response = bob_conn.recv(1024)
bob_final_response = json.loads(response.decode())
print("Trudy: Receive from Bob:", response.hex())

bob_decrypted_response = decrypt_3des(K_AB, bob_final_response["K_AB{N2-1, N3}"], 'ECB')
response_data = json.loads(bob_decrypted_response)

N2_received = int(response_data["N2-1"]) + 1  # make sure N2-1 is correct
N3 = int(response_data["N3"], 16)

# since trudy didn't know alice's N2, so they should not be the same
if int(N2, 16) != N2_received:
    print("Trudy: Sending final message.")

    # Step 4: Send K_AB{N3-1} back to Bob
    trudy_bob_msg = json.dumps({"K_AB{N3-1}": encrypt_3des(K_AB, str(N3 - 1), 'ECB')}).encode()
    bob_conn.send(trudy_bob_msg)
    print("Trudy to Bob: ", trudy_bob_msg.hex())

bob_conn.close()