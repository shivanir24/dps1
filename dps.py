----aes---

import socket
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

def pad(plaintext, block_size=128):
    padder = padding.PKCS7(block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    return padded_data

def unpad(padded_plaintext, block_size=128):
    unpadder = padding.PKCS7(block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext

def aes_encrypt(plaintext, key, mode):
    cipher = Cipher(algorithms.AES(key), mode, backend=default_backend())
    encryptor = cipher.encryptor()
    padded_plaintext = pad(plaintext)
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    return ciphertext

def aes_decrypt(ciphertext, key, mode):
    cipher = Cipher(algorithms.AES(key), mode, backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    plaintext = unpad(padded_plaintext)
    return plaintext

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 12345))
server_socket.listen(1)

print("Server is listening...")

while True:
    client_socket, addr = server_socket.accept()
    print(f"Connection from {addr} established")
    
    operation = client_socket.recv(1024).decode()  # Receive the operation (encrypt/decrypt)
    mode = client_socket.recv(1024).decode()  # Receive the mode (ECB, CBC, CFB)
    message = client_socket.recv(4096)  # Receive the message
    key = client_socket.recv(32)  # Receive the key
    iv = client_socket.recv(16)  # Receive the IV (if needed)

    if mode == "ECB":
        aes_mode = modes.ECB()
    elif mode == "CBC":
        aes_mode = modes.CBC(iv)
    elif mode == "CFB":
        aes_mode = modes.CFB(iv)
    
    if operation == "encrypt":
        result = aes_encrypt(message, key, aes_mode)
    elif operation == "decrypt":
        result = aes_decrypt(message, key, aes_mode)
    
    client_socket.send(result)  # Send the result back to the client
    client_socket.close()
----
import socket
import os

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 12345))

operation = input("Enter operation (encrypt/decrypt): ").strip().lower()
mode = input("Enter mode (ECB/CBC/CFB): ").strip().upper()
message = input("Enter message: ").strip().encode()

key = os.urandom(32)
iv = os.urandom(16)

client_socket.send(operation.encode())  # Send the operation to the server
client_socket.send(mode.encode())  # Send the mode to the server
client_socket.send(message)  # Send the message to the server
client_socket.send(key)  # Send the key to the server

if mode != "ECB":
    client_socket.send(iv)  # Send the IV to the server (for CBC/CFB modes)

result = client_socket.recv(4096)  # Receive the result from the server

print(f"Result: {result}")
client_socket.close()

------------RSA-----

import socket
import rsa

def generate_keys():
    public_key, private_key = rsa.newkeys(512)
    return public_key, private_key

def rsa_encrypt(plaintext, public_key):
    encrypted_message = rsa.encrypt(plaintext.encode(), public_key)
    return encrypted_message

def rsa_decrypt(ciphertext, private_key):
    decrypted_message = rsa.decrypt(ciphertext, private_key).decode()
    return decrypted_message

# Server Setup
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 12345))
server_socket.listen(1)

print("Server is listening...")

# Generate RSA keys
public_key, private_key = generate_keys()

while True:
    client_socket, addr = server_socket.accept()
    print(f"Connection from {addr} established")
    
    operation = client_socket.recv(1024).decode()  # Receive the operation (encrypt/decrypt)
    
    if operation == "encrypt":
        message = client_socket.recv(1024).decode()  # Receive the plaintext message
        result = rsa_encrypt(message, public_key)
    elif operation == "decrypt":
        ciphertext = client_socket.recv(4096)  # Receive the ciphertext message
        result = rsa_decrypt(ciphertext, private_key).encode()
    
    client_socket.send(result)  # Send the result back to the client
    client_socket.close()
----
import socket

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 12345))

operation = input("Enter operation (encrypt/decrypt): ").strip().lower()

client_socket.send(operation.encode())  # Send the operation to the server

if operation == "encrypt":
    message = input("Enter plaintext message: ").strip()
    client_socket.send(message.encode())  # Send the plaintext message to the server
elif operation == "decrypt":
    ciphertext = input("Enter ciphertext (in bytes format): ").strip().encode('latin1')
    client_socket.send(ciphertext)  # Send the ciphertext to the server

result = client_socket.recv(4096)  # Receive the result from the server

if operation == "decrypt":
    result = result.decode()  # Convert bytes back to string if decrypting

print(f"Result: {result}")
client_socket.close()
