import socket
import json
import secrets
import time
from util import encrypt_3des, decrypt_3des
from generate_shared_keys import K_A_KDC, K_B_KDC

# Original NS protocol
# Step 1: Request session key from KDC
N1 = secrets.token_bytes(8).hex()
alice_kdc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
alice_kdc.connect(('localhost', 2000))

# Alice send to KDC
alice_msg = json.dumps({'from': 'Alice', 'N1': N1, 'message': 'Alice wants Bob'}).encode()
alice_kdc.send(alice_msg)
print("Alice to KDC: ", alice_msg.hex())

# Alice receive from KDC
kdc_recv_msg = alice_kdc.recv(1024)
kdc_response = json.loads(kdc_recv_msg.decode())
print("Alice receive from KDC: ", kdc_recv_msg.hex())
alice_kdc.close()

kdc_response_decrypted = decrypt_3des(K_A_KDC, kdc_response['from_KDC'], 'ECB')
kdc_response_data = json.loads(kdc_response_decrypted)

# Step 2: Decrypt the ticket send ticket to Bob
K_AB = bytes.fromhex(kdc_response_data['K_AB'])
N2 = secrets.token_bytes(8).hex()
encrypted_N2 = encrypt_3des(K_AB, N2, 'ECB')
ticket = kdc_response_data["ticket"]

# Alice send to Bob
alice_bob2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
alice_bob2.connect(('localhost', 3000))
alice_bob_msg = json.dumps({"ticket": ticket, "K_AB{N2}": encrypted_N2}).encode()
alice_bob2.send(alice_bob_msg)
print("Alice to Bob: ", alice_bob_msg.hex())

# Step 3: Save ticket and encrypted nonce to a file for Trudy
with open("stolen_data.json", "w") as f:
    json.dump({"ticket": ticket, "K_AB{N2}": encrypted_N2}, f)

print("Alice: Ticket and nonce saved for Trudy.")

# for trudy attack purpose to wait
print("Alice: Waiting before sending next message...")  
time.sleep(20)  

# Step 4: Receive K_AB{N2-1, N3} from Bob
bob_recv_msg2 = alice_bob2.recv(1024)
bob_final_response = json.loads(bob_recv_msg2.decode())
print("Alice receive from Bob: ", bob_recv_msg2.hex())

bob_decrypted_response = decrypt_3des(K_AB, bob_final_response["K_AB{N2-1, N3}"], 'ECB')
response_data = json.loads(bob_decrypted_response)

N2_received = int(response_data["N2-1"]) + 1  # make sure N2-1 is correct
N3 = int(response_data["N3"], 16)

if int(N2, 16) == N2_received:
    print("Alice Verified N2-1 from Bob. Sending final message.")

    # Step 5: Send K_AB{N3-1} back to Bob
    alice_bob_msg2 = json.dumps({"K_AB{N3-1}": encrypt_3des(K_AB, str(N3 - 1), 'ECB')}).encode()
    alice_bob2.send(alice_bob_msg2)
    print("Alice to Bob: ", alice_bob_msg2.hex())

alice_bob2.close()