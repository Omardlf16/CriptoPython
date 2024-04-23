from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from shutil import copyfile

def cipher(password, size, salt, input_file, output_file):
    if size not in [128, 192, 256]:
        print('Size value not valid')
        return

    # Derive key using PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=size//8,
        salt=salt.encode(),
        iterations=100000,  # You may adjust the number of iterations as needed
        backend=default_backend()
    )
    key = kdf.derive(password.encode())

    # Read input file and encrypt data
    with open(input_file, 'rb') as f_in, open(output_file, 'wb') as fileOut:
        cipher = Cipher(algorithms.AES(key), modes.CBC(b'\x00' * 16), backend=default_backend())
        encryptor = cipher.encryptor()
        while True:
            chunk = f_in.read(8192)
            if not chunk:
                break
            fileOut.write(encryptor.update(chunk) + encryptor.finalize())

# Example usage
# cipher("mypassword", 256, "mysalt", "input.txt", "output.txt")
