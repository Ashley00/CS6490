import socket
import json
import secrets
import threading
from util import encrypt_3des, decrypt_3des
from generate_shared_keys import K_A_KDC, K_B_KDC


def handle_client(conn, address):
    """Handles a single client connection (Alice or Trudy)."""
    try:
        receive = conn.recv(1024)
        data_receive = receive.decode()
        data = json.loads(data_receive)

        if "ticket" in data:
            print(f"Bob: Received from {address}: {receive.hex()}")

            # Step 1: Verify ticket and complete handshake
            ticket_decrypted = decrypt_3des(K_B_KDC, data["ticket"], 'ECB')
            ticket_data = json.loads(ticket_decrypted)
            K_AB = bytes.fromhex(ticket_data["K_AB"])

            # Step 2: Process `K_AB{N2}`
            N2 = decrypt_3des(K_AB, data["K_AB{N2}"], 'ECB')
            N2_int = int(N2, 16)  # Convert hex to integer

            # Step 3: Generate N3 and send `K_AB{N2-1, N3}`
            N3 = secrets.token_bytes(8).hex()
            response = {"N2-1": str(N2_int - 1), "N3": N3}
            bob_alice_msg = json.dumps({"K_AB{N2-1, N3}": encrypt_3des(K_AB, json.dumps(response), 'ECB')}).encode()
            conn.send(bob_alice_msg)
            print(f"Bob: Sent to {address}: {bob_alice_msg.hex()}")

            # Step 4: Receive `K_AB{N3-1}` from Alice/Trudy
            alice_final_response = json.loads(conn.recv(1024).decode())
            N3_minus_1 = decrypt_3des(K_AB, alice_final_response["K_AB{N3-1}"], 'ECB')

            if int(N3_minus_1) == int(N3, 16) - 1:
                print(f"Bob: Authentication Complete: {address} is verified.")

    except Exception as e:
        print(f"Bob: Error handling connection from {address}: {e}")

    finally:
        conn.close()

def bob():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('localhost', 3000))
    server.listen(5)  # Allow up to 5 simultaneous connections
    print("Bob: Server started, listening for multiple connections...")

    while True:
        conn, address = server.accept()
        print(f"Bob: Connection received from {address}")

        # Create a new thread for each client
        threading.Thread(target=handle_client, args=(conn, address)).start()

if __name__ == "__main__":
    bob()

"""
# Original NS protocol
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

    if "ticket" in data:
        print("Bob receive from Alice: ", receive.hex())
        # Step 1: Verify ticket and complete handshake
        ticket_decrypted = decrypt_3des(K_B_KDC, data["ticket"], 'ECB')
        ticket_data = json.loads(ticket_decrypted)
        K_AB = bytes.fromhex(ticket_data["K_AB"])

        # Process `K_AB{N2}`
        N2 = decrypt_3des(K_AB, data["K_AB{N2}"], 'ECB')
        N2_int = int(N2, 16) # convert hex to integer

        # Generate N3 and send `K_AB{N2-1, N3}`
        N3 = secrets.token_bytes(8).hex()
        response = {"N2-1": str(N2_int - 1), "N3": N3}
        bob_alice_msg = json.dumps({"K_AB{N2-1, N3}": encrypt_3des(K_AB, json.dumps(response), 'ECB')}).encode()
        conn.send(bob_alice_msg)
        print("Bob to Alice: ", bob_alice_msg.hex())

        # Receive `K_AB{N3-1}` from Alice
        alice_final_response = json.loads(conn.recv(1024).decode())
        N3_minus_1 = decrypt_3des(K_AB, alice_final_response["K_AB{N3-1}"], 'ECB')
        
        if int(N3_minus_1) == int(N3, 16) - 1:
            print("Bob Authentication Complete: Alice is verified.")

    conn.close()
"""