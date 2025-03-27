import socket
import json
import secrets
from util import encrypt_3des, decrypt_3des
from generate_shared_keys import K_A_KDC, K_B_KDC

# Extended NS protocol
# start server socket, in port 3000
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(('localhost', 3000))
server.listen(5)
print("Bob started")

while True:
    conn, address = server.accept()
    receive = conn.recv(1024)
    data_receive = receive.decode()
    data = json.loads(data_receive)

    if "message" in data:
        print("Bob receive from Alice: ", data_receive)
        # Step 1: Send challenge to Alice
        NB = secrets.token_bytes(8).hex()
        bob_alice_msg = json.dumps({"K_B{N_B}": encrypt_3des(K_B_KDC, NB)}).encode()
        conn.send(bob_alice_msg)
        print("Bob to Alice: ", bob_alice_msg.hex())
    elif "ticket" in data:
        print("Bob receive from Alice: ", receive.hex())
        # Step 2: Verify ticket and complete handshake
        ticket_decrypted = decrypt_3des(K_B_KDC, data["ticket"])
        ticket_data = json.loads(ticket_decrypted)
        K_AB = bytes.fromhex(ticket_data["K_AB"])
        N_B_received = ticket_data["N_B"]

        # Process `K_AB{N2}`
        N2 = decrypt_3des(K_AB, data["K_AB{N2}"])
        N2_int = int(N2, 16) # convert hex to integer

        # Generate N3 and send `K_AB{N2-1, N3}`
        N3 = secrets.token_bytes(8).hex()
        response = {"N2-1": str(N2_int - 1), "N3": N3}
        bob_alice_msg = json.dumps({"K_AB{N2-1, N3}": encrypt_3des(K_AB, json.dumps(response))}).encode()
        conn.send(bob_alice_msg)
        print("Bob to Alice: ", bob_alice_msg.hex())

        # Receive `K_AB{N3-1}` from Alice
        alice_final_response = json.loads(conn.recv(1024).decode())
        N3_minus_1 = decrypt_3des(K_AB, alice_final_response["K_AB{N3-1}"])
        
        if int(N3_minus_1) == int(N3, 16) - 1:
            print("Bob Authentication Complete: Alice is verified.")

    conn.close()