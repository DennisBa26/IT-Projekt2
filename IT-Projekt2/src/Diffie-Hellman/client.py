import requests
import time
import base64
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.padding import PKCS7
import os

BASE_URL = 'http://127.0.0.1:4999'  # adjust Server IP

# Logging Setup
log_file = open('client_output_dh.txt', 'w')
csv_file = open('client_timings_dh.csv', 'w')
csv_file.write("Iteration,Key Generation Time (s),Shared Secret Time (s),AES Encryption Time (s)\n")

print("[Client] Starte Client...")
print("[Client] Verbinde mit Server und hole DH Parameter...")

# Fetch DH parameters from the server
response = requests.get(f'{BASE_URL}/init')
parameters_bytes = base64.b64decode(response.json()['parameters'])
parameters = serialization.load_pem_parameters(parameters_bytes)
print("[Client] DH Parameter erfolgreich empfangen")

for i in range(1000):
    print(f"\n[Client] Starte Iteration {i+1}")
    print("[Client] Generiere Client Schlüsselpaar...")
    
    # generate key
    start_time = time.time()
    client_private_key = parameters.generate_private_key()
    client_public_key = client_private_key.public_key()
    key_generation_time = time.time() - start_time
    
    print(f"[Client] Schlüsselgenerierung abgeschlossen in {key_generation_time:.6f} s")
    print("[Client] Sende Public Key zum Server...")
    
    # Serialize Public Key
    client_public_key_bytes = client_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Key exchange
    start_time = time.time()
    response = requests.post(f'{BASE_URL}/exchange', json={
        'public_key': base64.b64encode(client_public_key_bytes).decode('utf-8')
    })
    
    print("[Client] Server Public Key empfangen, generiere Shared Secret...")
    server_public_key_bytes = base64.b64decode(response.json()['public_key'])
    server_public_key = serialization.load_pem_public_key(server_public_key_bytes)
    shared_secret = client_private_key.exchange(server_public_key)
    shared_secret_time = time.time() - start_time
    
    print(f"[Client] Shared Secret generiert in {shared_secret_time:.6f} s")
    print("[Client] Hole Daten von der URL...")
    
    # Derive AES key
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_secret)
    
    # Fetch data from URL
    url = "https://ogcapi.hft-stuttgart.de/sta/icity_data_security/v1.1"
    response = requests.get(url)
    if response.status_code != 200:
        print("[Client] FEHLER: Konnte keine Daten von der URL abrufen")
        break
    
    print("[Client] Daten erfolgreich geholt, starte Verschlüsselung...")
    data_to_encrypt = response.content
    iv = os.urandom(16)
    
    # Encryption
    start_time = time.time()
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data_to_encrypt) + padder.finalize()
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    encryption_time = time.time() - start_time
    
    print(f"[Client] Verschlüsselung abgeschlossen in {encryption_time:.6f} s")
    print("[Client] Sende verschlüsselte Daten zum Server...")
    
    # Send encrypted data
    response = requests.post(f'{BASE_URL}/decrypt', json={
        'iv': base64.b64encode(iv).decode('utf-8'),
        'encrypted_data': base64.b64encode(ciphertext).decode('utf-8'),
        'public_key': base64.b64encode(client_public_key_bytes).decode('utf-8'),
        'key_generation_time': key_generation_time,
        'shared_secret_time': shared_secret_time
    })
    
    # Logging
    log_file.write(f"Iteration {i+1}: Key Generation: {key_generation_time:.6f} s, "
                   f"Shared Secret: {shared_secret_time:.6f} s, "
                   f"AES Encryption: {encryption_time:.6f} s\n")
    csv_file.write(f"{i+1},{key_generation_time:.6f},{shared_secret_time:.6f},{encryption_time:.6f}\n")
    
    print("[Client] Iteration abgeschlossen")

print("[Client] Alle Iterationen abgeschlossen, räume auf...")

# Cleanup
log_file.close()
csv_file.close()