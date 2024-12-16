import csv
import time
import requests
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# IP anpassen ZAIZAIZAI
SERVER_URL = "http://127.0.0.1:4999/key_exchange"

CSV_FILE = "client_timings.csv"
with open(CSV_FILE, mode='w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(["Timestamp", "Server Public Key", "Shared Secret", "Computation Time (s)"])

# generate Diffie-Hellman-Key for client
parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
client_private_key = parameters.generate_private_key()
client_public_key = client_private_key.public_key()

# Send public key of client to server
client_public_key_pem = client_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode()

print(client_public_key_pem);
start_time = time.time()
response = requests.post(SERVER_URL, json={"client_public_key": client_public_key_pem})
computation_time = time.time() - start_time


if response.status_code == 200:
    data = response.json()
    server_public_key_bytes = data["server_public_key"].encode()
    server_public_key = serialization.load_pem_public_key(
        server_public_key_bytes,
        backend=default_backend()
    )
    
    # calculate secret
    shared_secret = client_private_key.exchange(server_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_secret)
    
    print(f"Server Public Key: {data['server_public_key']}")
    print(f"Gemeinsames Geheimnis: {derived_key.hex()}")
    
    with open(CSV_FILE, mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([
            time.strftime("%Y-%m-%d %H:%M:%S"),
            data["server_public_key"],
            derived_key.hex(),
            round(computation_time, 6)
        ])
else:
    print(f"Fehler: {response.status_code}")
