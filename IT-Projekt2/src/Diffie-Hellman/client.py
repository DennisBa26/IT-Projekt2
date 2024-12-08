import socket
import time
import requests
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.padding import PKCS7
import os

# Helper function to ensure all bytes are sent


def send_data(conn, data):
    total_sent = 0
    while total_sent < len(data):
        sent = conn.send(data[total_sent:])
        if sent == 0:
            raise RuntimeError("Socket connection broken")
        total_sent += sent


# Open log and CSV files
log_file = open('client_output_dh.txt', 'w')
csv_file = open('client_timings_dh.csv', 'w')
csv_file.write(
    "Iteration,Key Generation Time (s),Shared Secret Time (s),AES Encryption Time (s)\n")

# Set up the client socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('192.168.0.104', 5000))  # Replace with your server's IP

# Receive DH parameters from the server
parameters_bytes = client_socket.recv(2048)
parameters = serialization.load_pem_parameters(parameters_bytes)
for i in range(1000):
    # Measure key generation time (once per client)
    start_time = time.time()
    client_private_key = parameters.generate_private_key()
    client_public_key = client_private_key.public_key()
    key_generation_time = time.time() - start_time

    # Send Client's public key to the server
    client_public_key_bytes = client_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
     )
    send_data(client_socket, client_public_key_bytes)

    # Measure shared secret generation time (once per client)
    start_time = time.time()
    server_public_key_bytes = client_socket.recv(2048)
    server_public_key = serialization.load_pem_public_key(
        server_public_key_bytes)
    shared_secret = client_private_key.exchange(server_public_key)
    shared_secret_time = time.time() - start_time

    # Derive AES key using shared secret
    aes_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,  # AES-256 key
    salt=None,
    info=b'handshake data',
    backend=default_backend()
    ).derive(shared_secret)

    # Fetch data from the URL to encrypt
    url = "https://ogcapi.hft-stuttgart.de/sta/icity_data_security/v1.1"
    response = requests.get(url)
    if response.status_code == 200:
        data_to_encrypt = response.content  # Data fetched from the URL
    else:
        log_file.write(
            f"Failed to fetch data from the URL at iteration {i+1}\n")
        client_socket.close()
        exit()
    # Prepare IV for AES encryption
    iv = os.urandom(16)
    # Measure AES encryption time
    start_time = time.time()
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv),
                    backend=default_backend())
    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data_to_encrypt) + padder.finalize()
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    encryption_time = time.time() - start_time

    # Send IV and encrypted data to the server
    send_data(client_socket, iv)
    send_data(client_socket, len(ciphertext).to_bytes(4, byteorder='big'))
    send_data(client_socket, ciphertext)

    # Wait for acknowledgment from the server
    ack = client_socket.recv(1024)
    if ack != b'ACK':
        log_file.write(
            f"Failed to receive acknowledgment at iteration {i+1}\n")
        break

    # Log times for this iteration
    log_file.write(f"Iteration {i+1}: Key Generation: {key_generation_time:.6f} s, Shared Secret:
    {shared_secret_time:.6f} s, AES Encryption: {encryption_time:.6f} s\n")
    csv_file.write(f"{i+1},{key_generation_time:.6f},{shared_secret_time:.6f},{encryption_time:.6f}\n")
    
    
# Close the connection and files
client_socket.close()
log_file.close()
csv_file.close()