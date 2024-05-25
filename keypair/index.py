from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import os

def keypair( passphrase):
    # Crear la carpeta de salida si no existe
    if not os.path.exists('./.secrets'):
        os.makedirs('./.secrets')

    # Generar la clave privada
    privateKey = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Serializar la clave privada con cifrado usando la frase de contraseña
    privateKeyPem = privateKey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode())
    )
    
    # Serializar la clave pública
    publicKey = privateKey.public_key()
    publicKeyPem = publicKey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Guardar la clave pública en un archivo
    with open('./.secrets/public.key', 'wb') as f:
        f.write(publicKeyPem)
    
    # Guardar la clave privada en un archivo
    with open('./.secrets/private.key', 'wb') as f:
        f.write(privateKeyPem)

    return "Done pair keys generated"
