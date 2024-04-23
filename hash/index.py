import base64
import hashlib

def hash_file(algorithm, input, encoding):
    if (algorithm not in ["md5","sha1","sha256","sha512"]) : return 'Algorithm selected not valid'
    if (encoding not in ["base64","base64URL","hex","binary"]) : return 'Encoding selected not valid'
    with open(input, 'rb') as f:
        data = f.read()
        h = hashlib.new(algorithm)
        hashlib.pbkdf2_hmac
        h.update(data)
        if encoding == 'binary':
            return h.digest()
        if encoding == 'hex':
            return h.hexdigest()
        if encoding == 'base64':
            return base64.b64encode(h.digest())
        if encoding == 'base64URL':
            return base64.urlsafe_b64encode(h.digest())

# Example usage
# algorithm = 'sha256'
# input_file_path = 'path/to/your/file.txt'
# hash_result = hash_file(algorithm, input_file_path)
# print(hash_result.hex())
