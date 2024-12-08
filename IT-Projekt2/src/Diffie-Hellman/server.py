import socket
import time
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.padding import PKCS7

# Helper function to ensure we read all bytes


def receive_data(conn, length):
    data = b''
    while len(data) < length:
        packet = conn.recv(length - len(data))
        if not packet:
            break
        data += packet
    return data


# Open log and CSV files
log_file = open('server_output_dh.txt', 'w')
csv_file = open('server_timings_dh.csv', 'w')
csv_file.write(
    "Iteration,Key Generation Time (s),Shared Secret Time (s),AES Decryption Time (s)\n")


# Set up the server
parameters = dh.generate_parameters(generator=2, key_size=2048)


# Set up the server socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('192.168.0.104', 5000))  # Replace with your server's IP
server_socket.listen(1)
print("Server listening on port 5000...")


conn, addr = server_socket.accept()
print(f"Connection established with {addr}")


# Send DH parameters to the client
parameters_bytes = parameters.parameter_bytes(
 encoding=serialization.Encoding.PEM,
 format=serialization.ParameterFormat.PKCS3
)
conn.sendall(parameters_bytes)


for i in range(1000):
    # Measure key generation time (once per server)
    start_time = time.time()
    server_private_key = parameters.generate_private_key()
    server_public_key = server_private_key.public_key()
    key_generation_time = time.time() - start_time

    # Send Server's public key to the client
    server_public_key_bytes = server_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
 )
    conn.sendall(server_public_key_bytes)

    # Measure shared secret generation time (once per server)
    start_time = time.time()
    client_public_key_bytes = receive_data(conn, 2048)
    client_public_key = serialization.load_pem_public_key(
        client_public_key_bytes)
    shared_secret = server_private_key.exchange(client_public_key)
    shared_secret_time = time.time() - start_time

    # Derive AES key using shared secret
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256 key
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_secret)

    # Receive IV and encrypted data
    iv = receive_data(conn, 16)  # Receive the IV
    encrypted_data_length = int.from_bytes(
        receive_data(conn, 4), byteorder='big')
    received_data = receive_data(conn, encrypted_data_length)

    # Measure AES decryption time
    start_time = time.time()
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv),
                    backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_message = decryptor.update(
        received_data) + decryptor.finalize()
    decryption_time = time.time() - start_time

    # Unpad the message
    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_message = unpadder.update(
        decrypted_padded_message) + unpadder.finalize()

    # Log times for this iteration
    log_file.write(f"Iteration {i+1}: Key Generation: {key_generation_time:.6f} s, Shared Secret:
    {shared_secret_time:.6f} s, AES Decryption: {decryption_time:.6f} s\n")
    csv_file.write(f"{i+1},{key_generation_time:.6f},{shared_secret_time:.6f},{decryption_time:.6f}\n")
    
    
    # Send acknowledgment to the client
    conn.sendall(b'ACK')
 
# Close the connection and files
conn.close()
server_socket.close()
log_file.close()
csv_file.close()