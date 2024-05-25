from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import base64

def to_encoding(value, encoding):
    if encoding == 'hex':
        return value.hex()
    elif encoding == 'base64':
        return base64.b64encode(value).decode('utf-8')
    elif encoding == 'binary':
        return value
    else:
        raise ValueError(f"Unsupported encoding: {encoding}")

def diffieHellman(encoding, from_params=None):
    if not from_params:
        # Generate DH parameters using the "modp14" group
        parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
        private_key = parameters.generate_private_key()
        public_key = private_key.public_key()
        
        prime = parameters.parameter_numbers().p
        generator = parameters.parameter_numbers().g

        publicKey = public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo)

        print(generator)
        
        return {
            "prime": to_encoding(prime.to_bytes((prime.bit_length() + 7) // 8, 'little'), encoding),
            "generator": to_encoding(generator.to_bytes((generator.bit_length() + 7) // 8, 'little'), encoding),
            "publicKey": to_encoding(publicKey, encoding),
            "privateKey": to_encoding(private_key.private_numbers().x.to_bytes((private_key.private_numbers().x.bit_length() + 7) // 8, 'little'), encoding)  # No share!!
        }
    else:
        prime_bytes = from_params['prime']
        generator_bytes = from_params['generator']
        
        prime = int.from_bytes(bytes.fromhex(prime_bytes) if encoding == 'hex' else base64.b64decode(prime_bytes), 'little')
        generator = int.from_bytes(bytes.fromhex(generator_bytes) if encoding == 'hex' else base64.b64decode(generator_bytes), 'little')
        
        parameters = dh.DHParameterNumbers(prime, generator).parameters(default_backend())
        
        private_key = parameters.generate_private_key()
        public_key = private_key.public_key()
        
        private_key = dh.DHPrivateKey().private_numbers().x.to_bytes((private_key.private_numbers().x.bit_length() + 7) // 8, 'little')
        public_key = private_key.public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        
        peer_public_key = dh.DHPublicKey().public_numbers()
        peer_public_key = peer_public_key.y.to_bytes((peer_public_key.y.bit_length() + 7) // 8, 'little')
        
        shared_key = private_key.exchange(peer_public_key)
        
        return {
            "prime": to_encoding(prime.to_bytes((prime.bit_length() + 7) // 8, 'little'), encoding),
            "generator": to_encoding(generator.to_bytes((generator.bit_length() + 7) // 8, 'little'), encoding),
            "publicKey": to_encoding(public_key, encoding),
            "privateKey": to_encoding(private_key, encoding),  # No share!!
            "secret": to_encoding(shared_key, encoding)
        }

# Usage
# encoding = 'base64'  # Change to 'hex' or 'binary' as needed

# # Example without from_params
# result = diffie_hellman(encoding)
# print(result)

# # Example with from_params
# from_params = {
#     "prime": result['prime'],
#     "generator": result['generator'],
#     "publicKey": result['publicKey'],
#     "privateKey": result['privateKey']
# }
# result_with_params = diffie_hellman(encoding, from_params=from_params)
# print(result_with_params)
