import socket
import json
import secrets
from util import encrypt_3des, decrypt_3des
from generate_shared_keys import K_A_KDC, K_B_KDC

# Extended NS protocol
# Step 1: Initiate request to Bob
alice_bob = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
alice_bob.connect(('localhost', 3000))

# Alice send to Bob
alice_bob.send(json.dumps({"message": "I want to talk"}).encode())
print("Alice to Bob: I want to talk")

# Alice receive from Bob
bob_recv_msg = alice_bob.recv(1024)
bob_response = json.loads(bob_recv_msg.decode())
print("Alice reveive from Bob: ", bob_recv_msg.hex())
alice_bob.close()

KB_NB = bob_response['K_B{N_B}']

# Step 2: Request session key from KDC
N1 = secrets.token_bytes(8).hex()
alice_kdc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
alice_kdc.connect(('localhost', 2000))

# Alice send to KDC
alice_msg = json.dumps({'from': 'Alice', 'N1': N1, 'message': 'Alice wants Bob', 'K_B{N_B}': KB_NB}).encode()
alice_kdc.send(alice_msg)
print("Alice to KDC: ", alice_msg.hex())

# Alice receive from KDC
kdc_recv_msg = alice_kdc.recv(1024)
kdc_response = json.loads(kdc_recv_msg.decode())
print("Alice receive from KDC: ", kdc_recv_msg.hex())
alice_kdc.close()

kdc_response_decrypted = decrypt_3des(K_A_KDC, kdc_response['from_KDC'])
kdc_response_data = json.loads(kdc_response_decrypted)

# Step 3: Decrypt the ticket using Bob’s key to extract K_AB, and send ticket to Bob
ticket_to_bob = kdc_response_data['ticket']
ticket_decrypted = decrypt_3des(K_B_KDC, ticket_to_bob)
ticket_data = json.loads(ticket_decrypted)

# extract K_AB from ticket
K_AB = bytes.fromhex(ticket_data['K_AB']) 

N2 = secrets.token_bytes(8).hex()

# Alice send to Bob
alice_bob2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
alice_bob2.connect(('localhost', 3000))
alice_bob_msg = json.dumps({"ticket": kdc_response_data["ticket"], "K_AB{N2}": encrypt_3des(K_AB, N2)}).encode()
alice_bob2.send(alice_bob_msg)
print("Alice to Bob: ", alice_bob_msg.hex())

# Step 4: Receive K_AB{N2-1, N3} from Bob
bob_recv_msg2 = alice_bob2.recv(1024)
bob_final_response = json.loads(bob_recv_msg2.decode())
print("Alice receive from Bob: ", bob_recv_msg2.hex())

bob_decrypted_response = decrypt_3des(K_AB, bob_final_response["K_AB{N2-1, N3}"])
response_data = json.loads(bob_decrypted_response)

N2_received = int(response_data["N2-1"]) + 1  # make sure N2-1 is correct
N3 = int(response_data["N3"], 16)

if int(N2, 16) == N2_received:
    print("Alice Verified N2-1 from Bob. Sending final message.")

    # Step 5: Send K_AB{N3-1} back to Bob
    alice_bob_msg2 = json.dumps({"K_AB{N3-1}": encrypt_3des(K_AB, str(N3 - 1))}).encode()
    alice_bob2.send(alice_bob_msg2)
    print("Alice to Bob: ", alice_bob_msg2.hex())

alice_bob2.close()