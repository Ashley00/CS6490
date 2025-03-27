import socket
import json
import secrets
from util import encrypt_3des, decrypt_3des
from generate_shared_keys import K_A_KDC, K_B_KDC

# Original NS protocol
# start the KDC socket, in port 2000
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(('localhost', 2000))
server.listen(5)
print("KDC started")

while True:
    connection, address = server.accept()
    data = json.loads(connection.recv(1024).decode())

    if data['from'] == 'Alice': # check if the data is from Alice
        N1 = data['N1']
        msg = data['message']
        
        # generate session key K_AB
        K_AB = secrets.token_bytes(24).hex()

        # ticket for Bob
        ticket_to_bob = encrypt_3des(K_B_KDC, json.dumps({"K_AB": K_AB, "Alice": "Alice"}), 'ECB')

        # send response to Alice
        response = {'from_KDC': encrypt_3des(K_A_KDC, json.dumps({"N1": N1, "Bob": "Bob", "K_AB": K_AB, "ticket": ticket_to_bob}), 'ECB')}
        kdc_alice = json.dumps(response).encode()
        connection.send(kdc_alice)
        print("KDC to Alice: ", kdc_alice.hex())
    else:
        print("Unknow connection")

    connection.close()