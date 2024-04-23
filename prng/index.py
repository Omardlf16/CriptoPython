import secrets

def prng(type, size=None, min=None, max=None, encode=None):
    if type == "bytes":
        return secrets.token_bytes(size).hex() if encode == "hex" else secrets.token_bytes(size)
    elif type == "int":
        return secrets.randbelow(max - min + 1) + min
    elif type == "uuid":
        return secrets.token_urlsafe()

# Example usage
# print(prng("bytes", size=16, encode="hex"))
# print(prng("int", min=0, max=100))
# print(prng("uuid"))
