from flask import Flask, request, jsonify
import time
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.padding import PKCS7
import base64

app = Flask(__name__)

# Global variabels for server status
parameters = None
server_private_key = None
server_public_key = None
iteration = 0

# files for logging
log_file = open('server_output_dh.txt', 'w')
csv_file = open('server_timings_dh.csv', 'w')
csv_file.write("Iteration,Key Generation Time (s),Shared Secret Time (s),AES Decryption Time (s)\n")

@app.route('/init', methods=['GET'])
def init_connection():
    global parameters, server_private_key, server_public_key, iteration
    
    print("\n[Server] Neue Verbindung initialisiert")
    print("[Server] Generiere DH Parameter...")
    
    parameters = dh.generate_parameters(generator=2, key_size=2048)
    parameters_bytes = parameters.parameter_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.ParameterFormat.PKCS3
    )
    
    print("[Server] DH Parameter generiert und werden zum Client gesendet")
    return jsonify({
        'parameters': base64.b64encode(parameters_bytes).decode('utf-8')
    })

@app.route('/exchange', methods=['POST'])
def key_exchange():
    global parameters, server_private_key, server_public_key, iteration
    iteration += 1
    
    print(f"\n[Server] Starte Schlüsselaustausch für Iteration {iteration}")
    print("[Server] Generiere Server Schlüsselpaar...")
    
    # generate server key 
    start_time = time.time()
    server_private_key = parameters.generate_private_key()
    server_public_key = server_private_key.public_key()
    key_generation_time = time.time() - start_time
    
    print(f"[Server] Schlüsselgenerierung abgeschlossen in {key_generation_time:.6f} s")
    print("[Server] Empfange Client Public Key...")
    
    # Receive Client Public Key
    client_data = request.json
    client_public_key_bytes = base64.b64decode(client_data['public_key'])
    
    print("[Server] Generiere Shared Secret...")
    # generate Shared Secret 
    start_time = time.time()
    client_public_key = serialization.load_pem_public_key(client_public_key_bytes)
    shared_secret = server_private_key.exchange(client_public_key)
    shared_secret_time = time.time() - start_time
    
    print(f"[Server] Shared Secret generiert in {shared_secret_time:.6f} s")
    print("[Server] Sende Server Public Key zum Client...")
    
    # Send Server Public Key
    server_public_key_bytes = server_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return jsonify({
        'public_key': base64.b64encode(server_public_key_bytes).decode('utf-8')
    })

@app.route('/decrypt', methods=['POST'])
def decrypt_data():
    global server_private_key, iteration
    
    print(f"\n[Server] Starte Entschlüsselung für Iteration {iteration}")
    print("[Server] Empfange verschlüsselte Daten...")
    
    data = request.json
    iv = base64.b64decode(data['iv'])
    encrypted_data = base64.b64decode(data['encrypted_data'])
    
    print("[Server] Leite AES Schlüssel ab...")
    # Derive AES key
    shared_secret = server_private_key.exchange(
        serialization.load_pem_public_key(
            base64.b64decode(data['public_key'])
        )
    )
    
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_secret)
    
    # Measure decryption
    start_time = time.time()
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_message = decryptor.update(encrypted_data) + decryptor.finalize()
    decryption_time = time.time() - start_time
    
    # Entpadding
    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_message = unpadder.update(decrypted_padded_message) + unpadder.finalize()
    
    # Logging
    log_file.write(f"Iteration {iteration}: Key Generation: {data['key_generation_time']:.6f} s, "
                   f"Shared Secret: {data['shared_secret_time']:.6f} s, "
                   f"AES Decryption: {decryption_time:.6f} s\n")
    csv_file.write(f"{iteration},{data['key_generation_time']:.6f},"
                   f"{data['shared_secret_time']:.6f},{decryption_time:.6f}\n")
    
    print(f"[Server] Entschlüsselung abgeschlossen in {decryption_time:.6f} s")
    return jsonify({'status': 'success'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=4999)