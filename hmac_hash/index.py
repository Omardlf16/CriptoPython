from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac
import base64
from cryptography.hazmat.backends import default_backend

def hmac_hash(algorithm, key, input_file_path, encoding):
    if (algorithm not in ["md5","sha1","sha256","sha512"]) : return 'Algorithm selected not valid'
    if (encoding not in ["base64","base64URL","hex","binary"]) : return 'Encoding selected not valid'
    algorithmSelector = {
        "md5": hashes.MD5(), "sha1": hashes.SHA1(), "sha256": hashes.SHA256(), "sha512": hashes.SHA512()
    }
    with open(input_file_path, 'rb') as f:
        data = f.read()
        h = hmac.HMAC(key.encode('utf-8'), algorithmSelector[algorithm], backend=default_backend())
        h.update(data)
        if encoding == 'binary':
            return h.finalize()
        if encoding == 'hex':
            return h.finalize().hex()
        if encoding == 'base64':
            return base64.b64encode(h.finalize())
        if encoding == 'base64URL':
            return base64.urlsafe_b64encode(h.finalize())

# Example usage
# algorithm = 'SHA256'
# key = b'SecretKey'  # Note: In Python, keys should be bytes
# input_file_path = 'path/to/your/file.txt'
# hash_result = hmac_hash(algorithm, key, input_file_path)
# print(hash_result.hex())






# from cryptography.hazmat.primitives import hashes, hmac
# import hashlib
# from cryptography.hazmat.backends import default_backend

# def hmac_hash(algorithm, key, input, encoding):
#     if (algorithm not in ["md5","sha1","sha256","sha512"]) : return 'Algorithm selected not valid'
#     if (encoding not in ["base64","base64URL","hex","binary"]) : return 'Encoding selected not valid'
#     with open(input, 'rb') as f:
#         data = f.read()
#         h = hmac.HMAC(key.encode('utf-8'), hashlib.new(algorithm), backend=default_backend())
#         h.update(data)
#         return h.finalize()

# # Example usage
# # algorithm = 'SHA256'
# # key = b'SecretKey'  # Note: In Python, keys should be bytes
# # input = 'path/to/your/file.txt'
# # hash_result = hmac_hash(algorithm, key, input)
# # print(hash_result.hex())
