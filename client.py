import socket
import os
import hashlib
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto import Random

# generate a key based on a password and salt
def generate_key(password, salt):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)

def encrypt_data(data, key):
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CFB, iv)
    encrypted_data = iv + cipher.encrypt(data)
    return encrypted_data

def decrypt_data(encrypted_data, key):
    iv = encrypted_data[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CFB, iv)
    decrypted_data = cipher.decrypt(encrypted_data[AES.block_size:])
    return decrypted_data

def encrypt_key(key, public_key):
    encrypted_key = public_key.encrypt(key, 32)[0]
    return encrypted_key

def decrypt_key(encrypted_key, private_key):
    decrypted_key = private_key.decrypt(encrypted_key)
    return decrypted_key

serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

host = '127.0.0.1'

port = 9999

serversocket.connect((host, port))

key = generate_key("password", b"salt")

public_key = RSA.importKey(serversocket.recv(2048))

encrypted_key = encrypt_key(key, public_key)
serversocket.send(encrypted_key)

msg = "Hello from the client!"
encrypted_msg = encrypt_data(msg.encode('utf-8'), key)
serversocket.send(encrypted_msg)

data = serversocket.recv(1024)
decrypted_data = decrypt_data(data, key)
print(decrypted_data.decode('utf-8'))

serversocket.close()
