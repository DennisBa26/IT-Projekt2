import csv
import time
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)

parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
server_private_key = parameters.generate_private_key()
server_public_key = server_private_key.public_key()

CSV_FILE = "server_timings.csv"
with open(CSV_FILE, mode='w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(["Timestamp", "Client Public Key", "Shared Secret", "Computation Time (s)"])

@app.route('/key_exchange', methods=['POST'])
def key_exchange():
    # get public key  of clients
    start_time = time.time()
    client_public_key_bytes = request.json.get("client_public_key").encode()
    print(f"Empfangener Client Public Key:\n{client_public_key_bytes.decode()}") 

    client_public_key = serialization.load_pem_public_key(
        client_public_key_bytes,
        backend=default_backend()
    )
    
    # calculate secret
    shared_secret = server_private_key.exchange(client_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_secret)
    computation_time = time.time() - start_time
    
    print("Gemeinsames Geheimnis berechnet.")
    
    with open(CSV_FILE, mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([
            time.strftime("%Y-%m-%d %H:%M:%S"),
            client_public_key_bytes.decode(),
            derived_key.hex(),
            round(computation_time, 6)
        ])
    
    # send back the server public key
    server_public_key_pem = server_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    
    return jsonify({
        "server_public_key": server_public_key_pem,
        "shared_secret": derived_key.hex()
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=4999)
